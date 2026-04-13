"""
SAST Finding Analyzer — triages SAST scanner findings (Wiz, Semgrep, Checkmarx, etc.)
to determine true positive, false positive, or inconclusive verdict.

Enriches with CWE/CAPEC/ATT&CK intelligence and uses LLM analysis.
Returns verdict, confidence, reasoning, and follow-up questions when context is missing.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from langchain_core.messages import HumanMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.base import SecurityTool, ToolResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CWE categories for missing-context detection
# ---------------------------------------------------------------------------

# CWEs where data source trust and sanitization are critical to the verdict
_DATA_FLOW_CWES = {
    "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91", "CWE-94", "CWE-95",
    "CWE-96", "CWE-116", "CWE-134", "CWE-138", "CWE-176", "CWE-390",
    "CWE-472", "CWE-502", "CWE-611", "CWE-917", "CWE-918",
    "CWE-22", "CWE-23", "CWE-36", "CWE-73",
}

# CWEs where authentication and deployment context matter most
_ACCESS_CONTROL_CWES = {
    "CWE-284", "CWE-285", "CWE-287", "CWE-306", "CWE-307", "CWE-352",
    "CWE-384", "CWE-613", "CWE-614", "CWE-798", "CWE-862", "CWE-863",
}

# Questions for each missing context field
_CONTEXT_QUESTIONS: Dict[str, Dict[str, str]] = {
    "data_source_trust": {
        "question": (
            "Where does the data used in this code originate? "
            "Is it an internal database, external API, user input, config file, or environment variable?"
        ),
        "why_it_matters": (
            "Data-flow vulnerabilities like this CWE are only exploitable when "
            "the data source can be influenced by an attacker. Internal databases "
            "populated by trusted pipelines have very different risk profiles than "
            "direct user input."
        ),
    },
    "sanitization_present": {
        "question": (
            "Is there any input validation, sanitization, or parameterization "
            "applied to the data before it reaches this code?"
        ),
        "why_it_matters": (
            "Upstream sanitization can neutralize the attack vector entirely. "
            "For example, parameterized SQL prevents injection even with untrusted input."
        ),
    },
    "deployment_context": {
        "question": (
            "Is this code deployed in an internet-facing service, internal-only service, "
            "or air-gapped environment?"
        ),
        "why_it_matters": (
            "Deployment context determines attacker reachability. An internet-facing "
            "endpoint is directly exploitable, while internal-only services require "
            "network access first."
        ),
    },
    "authentication_required": {
        "question": (
            "Does the code path that reaches this code require authentication? "
            "Is it behind a login or API key check?"
        ),
        "why_it_matters": (
            "Authentication gates reduce the attack surface by limiting who can "
            "reach the vulnerable code. Unauthenticated endpoints are higher risk."
        ),
    },
}


# ---------------------------------------------------------------------------
# Input schema
# ---------------------------------------------------------------------------


class SASTFindingAnalyzerInput(BaseModel):
    cwe_id: str = Field(description="CWE ID flagged by the SAST tool, e.g. CWE-472")
    code_snippet: str = Field(description="The code snippet flagged by the SAST scanner")
    file_path: str = Field(description="File path where the finding was reported")
    sast_description: str = Field(
        description="The SAST tool's finding title/description, e.g. 'Untrusted Data Poisoning Agent Memory'"
    )
    sast_tool_name: Optional[str] = Field(
        default=None,
        description="Name of the SAST scanner, e.g. 'Wiz', 'Semgrep', 'Checkmarx'",
    )
    line_number: Optional[int] = Field(default=None, description="Line number of the finding")
    data_source_trust: Optional[str] = Field(
        default=None,
        description=(
            "Trust level of the data source: "
            "'internal_db', 'external_api', 'user_input', 'config_file', "
            "'environment_variable', 'unknown'"
        ),
    )
    sanitization_present: Optional[bool] = Field(
        default=None,
        description="Whether input sanitization/validation is present in the code path",
    )
    deployment_context: Optional[str] = Field(
        default=None,
        description="Deployment context: 'internal_only', 'internet_facing', 'air_gapped', 'unknown'",
    )
    authentication_required: Optional[bool] = Field(
        default=None,
        description="Whether the code path requires authentication to reach",
    )
    additional_context: Optional[str] = Field(
        default=None,
        description="Any additional context about the code, its purpose, or environment",
    )


# ---------------------------------------------------------------------------
# Missing-context detection (deterministic, no LLM)
# ---------------------------------------------------------------------------


def _detect_missing_context(
    cwe_id: str,
    *,
    data_source_trust: Optional[str],
    sanitization_present: Optional[bool],
    deployment_context: Optional[str],
    authentication_required: Optional[bool],
) -> List[Dict[str, str]]:
    """Return list of follow-up questions for missing context fields."""
    cid = cwe_id.strip().upper()
    missing: List[Dict[str, str]] = []

    # Data-flow CWEs need data source trust and sanitization info
    if cid in _DATA_FLOW_CWES:
        if data_source_trust is None:
            q = _CONTEXT_QUESTIONS["data_source_trust"]
            missing.append({"field": "data_source_trust", **q})
        if sanitization_present is None:
            q = _CONTEXT_QUESTIONS["sanitization_present"]
            missing.append({"field": "sanitization_present", **q})

    # Access-control CWEs need auth and deployment info
    if cid in _ACCESS_CONTROL_CWES:
        if authentication_required is None:
            q = _CONTEXT_QUESTIONS["authentication_required"]
            missing.append({"field": "authentication_required", **q})

    # All CWEs benefit from deployment context
    if deployment_context is None:
        q = _CONTEXT_QUESTIONS["deployment_context"]
        missing.append({"field": "deployment_context", **q})

    return missing


# ---------------------------------------------------------------------------
# LLM helpers
# ---------------------------------------------------------------------------


def _extract_json_block(text: str) -> Any:
    text = (text or "").strip()
    if "```" in text:
        m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if m:
            text = m.group(1).strip()
    return json.loads(text)


def _build_context_fields_json(
    data_source_trust: Optional[str],
    sanitization_present: Optional[bool],
    deployment_context: Optional[str],
    authentication_required: Optional[bool],
    additional_context: Optional[str],
) -> str:
    fields: Dict[str, Any] = {}
    if data_source_trust is not None:
        fields["data_source_trust"] = data_source_trust
    if sanitization_present is not None:
        fields["sanitization_present"] = sanitization_present
    if deployment_context is not None:
        fields["deployment_context"] = deployment_context
    if authentication_required is not None:
        fields["authentication_required"] = authentication_required
    if additional_context is not None:
        fields["additional_context"] = additional_context
    if not fields:
        return "No additional context provided."
    return json.dumps(fields, indent=2)


# ---------------------------------------------------------------------------
# Tool implementation
# ---------------------------------------------------------------------------


class SASTFindingAnalyzerTool(SecurityTool):
    @property
    def tool_name(self) -> str:
        return "sast_finding_analyzer"

    def cache_key(self, **kwargs) -> str:
        return f"sast:{kwargs.get('cwe_id')}:{kwargs.get('file_path')}:{kwargs.get('line_number')}"

    def execute(
        self,
        cwe_id: str,
        code_snippet: str,
        file_path: str,
        sast_description: str,
        sast_tool_name: Optional[str] = None,
        line_number: Optional[int] = None,
        data_source_trust: Optional[str] = None,
        sanitization_present: Optional[bool] = None,
        deployment_context: Optional[str] = None,
        authentication_required: Optional[bool] = None,
        additional_context: Optional[str] = None,
    ) -> ToolResult:
        ts = datetime.utcnow().isoformat()
        cid = cwe_id.strip().upper()
        if not cid.startswith("CWE-"):
            cid = f"CWE-{cid.replace('CWE-', '').replace('cwe-', '')}"

        # ------------------------------------------------------------------
        # Step 1: CWE enrichment
        # ------------------------------------------------------------------
        cwe_data: Dict[str, Any] = {}
        linked_capec_ids: List[str] = []
        try:
            from asteraskills.tools.cwe_capec_cis_tools import CWELookupTool

            cwe_result = CWELookupTool().execute(cwe_id=cid, include_capec_links=True)
            if cwe_result.success and cwe_result.data:
                cwe_data = cwe_result.data
                linked_capec_ids = cwe_data.get("linked_capec_ids", [])
        except Exception as e:
            logger.warning("CWE lookup failed for %s: %s", cid, e)

        cwe_definition = "Not available"
        if cwe_data.get("postgres"):
            pg = cwe_data["postgres"]
            cwe_definition = f"{pg.get('cwe_id', cid)} — {pg.get('name', 'Unknown')}\n{pg.get('description', '')}"

        # ------------------------------------------------------------------
        # Step 2: ATT&CK mappings via cwe_to_attack_intel
        # ------------------------------------------------------------------
        attack_mappings: Dict[str, Any] = {"technique_mappings": [], "cwe_capec_attack_mappings": []}
        try:
            from asteraskills.tools.cwe_capec_cis_tools import create_cwe_to_attack_intel_tool

            attack_tool = create_cwe_to_attack_intel_tool()
            attack_result = attack_tool.invoke({"cwe_id": cid})
            if isinstance(attack_result, dict) and attack_result.get("success"):
                attack_mappings = attack_result.get("data", attack_mappings)
        except Exception as e:
            logger.warning("ATT&CK mapping failed for %s: %s", cid, e)

        # ------------------------------------------------------------------
        # Step 3: CAPEC enrichment (up to 3 linked patterns)
        # ------------------------------------------------------------------
        capec_details: List[Dict[str, Any]] = []
        try:
            from asteraskills.tools.cwe_capec_cis_tools import CAPECLookupTool

            capec_tool = CAPECLookupTool()
            for capec_id in linked_capec_ids[:3]:
                try:
                    cr = capec_tool.execute(capec_id=capec_id)
                    if cr.success and cr.data and cr.data.get("postgres"):
                        capec_details.append(cr.data["postgres"])
                except Exception:
                    pass
        except Exception as e:
            logger.warning("CAPEC lookup failed: %s", e)

        # ------------------------------------------------------------------
        # Step 4: Missing context detection
        # ------------------------------------------------------------------
        missing_context = _detect_missing_context(
            cid,
            data_source_trust=data_source_trust,
            sanitization_present=sanitization_present,
            deployment_context=deployment_context,
            authentication_required=authentication_required,
        )

        # ------------------------------------------------------------------
        # Step 5: LLM analysis
        # ------------------------------------------------------------------
        llm_verdict: Optional[Dict[str, Any]] = None
        try:
            from asteraskills.core.llm import get_llm
            from risk_scanner.core.prompts import format_prompt

            context_json = _build_context_fields_json(
                data_source_trust=data_source_trust,
                sanitization_present=sanitization_present,
                deployment_context=deployment_context,
                authentication_required=authentication_required,
                additional_context=additional_context,
            )

            prompt_text = format_prompt(
                "PROMPT-18",
                cwe_id=cid,
                cwe_definition=cwe_definition,
                code_snippet=code_snippet,
                file_path=file_path,
                sast_description=sast_description,
                sast_tool_name=sast_tool_name or "Unknown",
                capec_patterns=json.dumps(capec_details, indent=2) if capec_details else "None available",
                attack_mappings=json.dumps(attack_mappings, indent=2),
                context_fields=context_json,
            )

            llm = get_llm(temperature=0.2)
            resp = llm.invoke([HumanMessage(content=prompt_text)])
            raw = resp.content if hasattr(resp, "content") else str(resp)
            llm_verdict = _extract_json_block(raw)
        except Exception as e:
            logger.warning("LLM analysis failed: %s", e)

        # ------------------------------------------------------------------
        # Step 6: Assemble result
        # ------------------------------------------------------------------
        result_data: Dict[str, Any] = {
            "cwe_id": cid,
            "file_path": file_path,
            "line_number": line_number,
            "sast_tool": sast_tool_name,
            "cwe_details": cwe_data,
            "attack_mappings": attack_mappings,
            "capec_patterns": capec_details,
            "missing_context": missing_context,
        }

        if llm_verdict:
            result_data["verdict"] = llm_verdict.get("verdict", "inconclusive")
            result_data["confidence"] = llm_verdict.get("confidence", 0.0)
            result_data["reasoning"] = llm_verdict.get("reasoning", "")
            result_data["key_factors"] = llm_verdict.get("key_factors", [])
            result_data["remediation"] = llm_verdict.get("remediation")
            result_data["ignore_justification"] = llm_verdict.get("ignore_justification")
            result_data["wiz_ignore_comment"] = llm_verdict.get("wiz_ignore_comment")
            result_data["risk_if_wrong"] = llm_verdict.get("risk_if_wrong")
        else:
            result_data["verdict"] = "inconclusive"
            result_data["confidence"] = 0.0
            result_data["reasoning"] = (
                "LLM analysis unavailable. Enrichment data (CWE/CAPEC/ATT&CK) is provided "
                "for manual review."
            )
            result_data["key_factors"] = []
            result_data["remediation"] = None
            result_data["ignore_justification"] = None
            result_data["wiz_ignore_comment"] = None
            result_data["risk_if_wrong"] = None

        return ToolResult(
            success=True,
            data=result_data,
            source="sast_finding_analyzer",
            timestamp=ts,
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_sast_finding_analyzer_tool() -> StructuredTool:
    tool = SASTFindingAnalyzerTool()

    def _go(
        cwe_id: str,
        code_snippet: str,
        file_path: str,
        sast_description: str,
        sast_tool_name: Optional[str] = None,
        line_number: Optional[int] = None,
        data_source_trust: Optional[str] = None,
        sanitization_present: Optional[bool] = None,
        deployment_context: Optional[str] = None,
        authentication_required: Optional[bool] = None,
        additional_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        return tool.execute(
            cwe_id=cwe_id,
            code_snippet=code_snippet,
            file_path=file_path,
            sast_description=sast_description,
            sast_tool_name=sast_tool_name,
            line_number=line_number,
            data_source_trust=data_source_trust,
            sanitization_present=sanitization_present,
            deployment_context=deployment_context,
            authentication_required=authentication_required,
            additional_context=additional_context,
        ).to_dict()

    return StructuredTool.from_function(
        func=_go,
        name="sast_finding_analyzer",
        description=(
            "Analyze a SAST finding to determine if it is a true positive, false positive, "
            "or inconclusive. Takes a CWE ID, code snippet, file path, and SAST tool description. "
            "Enriches with CWE/CAPEC/ATT&CK data and uses LLM analysis. Returns verdict, "
            "confidence, reasoning, and missing context questions for follow-up."
        ),
        args_schema=SASTFindingAnalyzerInput,
    )
