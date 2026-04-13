"""
AttackControlMappingTool — orchestrate ATT&CK technique → control mapping pipeline.
Calls TacticContextualiserTool, FrameworkItemRetrievalTool, then LLM mapping + validation.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from asteraskills.tools.attack_tools import ATTACKEnrichmentTool
from asteraskills.config.settings import get_settings
from asteraskills.ingestion.attacktocve.prompts import (
    CONTROL_MAPPING_SYSTEM,
    CONTROL_MAPPING_SYSTEM_NO_CANDIDATES,
    CONTROL_MAPPING_USER,
    CONTROL_MAPPING_USER_NO_CANDIDATES,
    VALIDATION_SYSTEM,
    VALIDATION_USER,
    get_framework_preset,
)

logger = logging.getLogger(__name__)

def _get_tactic_context(technique_id: str, tactic: str) -> Dict[str, Any]:
    from asteraskills.tools.tactic_contextualiser import _execute_tactic_contextualise
    return _execute_tactic_contextualise(technique_id, tactic)


def _get_framework_items(
    query: str,
    framework_id: str,
    tactic: str,
    top_k: int,
) -> List[Dict[str, Any]]:
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval
    return _execute_framework_item_retrieval(query, framework_id, tactic, top_k, 0.35)


def _get_framework_items_stage3(
    query: str,
    framework_id: str,
    tactic: str,
    top_k: int,
) -> List[Dict[str, Any]]:
    """Stage 3: tactic filter → broad vector → YAML; may be empty (LLM-only fallback)."""
    from asteraskills.tools.framework_item_retrieval import get_framework_items_stage3_with_fallback

    return get_framework_items_stage3_with_fallback(query, framework_id, tactic, top_k, 0.35)


def _get_framework_metadata(framework_id: str) -> tuple[str, str]:
    """Lookup framework_name and control_id_label from control_frameworks or prompts."""
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        with get_security_intel_session("cve_attack") as session:
            result = session.execute(
                text("SELECT framework_name, control_id_label FROM control_frameworks WHERE framework_id = :fid"),
                {"fid": framework_id},
            )
            row = result.fetchone()
            if row:
                return (row[0] or framework_id, row[1] or "item_id")
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.debug(f"control_frameworks lookup failed: {e}")
    preset = get_framework_preset(framework_id)
    return (
        preset.get("framework_name", framework_id),
        preset.get("control_id_label", "item_id"),
    )


class AttackControlMappingInput(BaseModel):
    """Input schema for AttackControlMappingTool."""
    technique_id: str = Field(description="ATT&CK technique ID (e.g., T1078)")
    tactic: str = Field(description="Kill chain phase slug (e.g., persistence)")
    framework_id: str = Field(description="Framework ID (e.g., nist_800_53r5, cis_v8_1)")
    top_k: int = Field(default=8, description="Number of candidate items to retrieve")
    cve_id: Optional[str] = Field(default=None, description="Optional CVE ID for CVE pipeline context")
    cve_context: Optional[Dict[str, Any]] = Field(default=None, description="Optional CVE detail for richer rationale")
    persist: bool = Field(default=True, description="Persist mappings to attack_control_mappings_multi")


class ControlMappingResult(BaseModel):
    """Single control mapping result."""
    technique_id: str
    tactic: str
    item_id: str
    framework_id: str
    relevance_score: float
    confidence: str
    rationale: str
    tactic_risk_lens: str
    blast_radius: str
    control_family: str
    attack_tactics: List[str]
    attack_platforms: List[str]
    loss_outcomes: List[str]


def _extract_json(text: str) -> Any:
    """Extract JSON from LLM response (handle markdown fences)."""
    text = text.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if match:
            text = match.group(1).strip()
    return json.loads(text)


def _get_existing_control_mappings(
    technique_id: str,
    tactic: str,
    framework_id: str,
) -> List[Dict[str, Any]]:
    """Return existing control mappings for (technique_id, tactic, framework_id) from attack_control_mappings_multi."""
    try:
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        tid = technique_id.strip().upper()
        tactic_slug = tactic.strip().lower().replace(" ", "-")
        fid = framework_id.strip().lower()

        with get_security_intel_session("cve_attack") as session:
            result = session.execute(
                text("""
                    SELECT item_id, relevance_score, confidence, rationale,
                           tactic_risk_lens, blast_radius, attack_tactics, attack_platforms, loss_outcomes
                    FROM attack_control_mappings_multi
                    WHERE technique_id = :tid AND tactic = :tactic AND framework_id = :fid
                """),
                {"tid": tid, "tactic": tactic_slug, "fid": fid},
            )
            rows = result.fetchall()
            if not rows:
                return []
            return [
                {
                    "technique_id": tid,
                    "tactic": tactic_slug,
                    "item_id": row[0],
                    "framework_id": fid,
                    "relevance_score": float(row[1]) if row[1] is not None else 0.5,
                    "confidence": row[2] or "medium",
                    "rationale": row[3] or "",
                    "tactic_risk_lens": row[4] or "",
                    "blast_radius": row[5] or "identity",
                    "attack_tactics": row[6] or [],
                    "attack_platforms": row[7] or [],
                    "loss_outcomes": row[8] or [],
                }
                for row in rows
            ]
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.debug(f"_get_existing_control_mappings failed: {e}")
        return []


def _persist_control_mappings_multi(
    results: List[Dict[str, Any]],
    cve_id: Optional[str] = None,
    mapping_run_id: Optional[str] = None,
    batch_size: int = 500,
) -> int:
    """Persist mappings to attack_control_mappings_multi table (batched executemany)."""
    if not results:
        return 0
    try:
        import uuid
        from asteraskills.storage.sqlalchemy_session import get_security_intel_session
        from sqlalchemy import text

        run_id = mapping_run_id or str(uuid.uuid4())
        stmt = text("""
                        INSERT INTO attack_control_mappings_multi (
                            technique_id, tactic, item_id, framework_id,
                            relevance_score, confidence, rationale,
                            tactic_risk_lens, blast_radius,
                            attack_tactics, attack_platforms, loss_outcomes,
                            mapping_run_id, cve_id
                        ) VALUES (
                            :technique_id, :tactic, :item_id, :framework_id,
                            :relevance_score, :confidence, :rationale,
                            :tactic_risk_lens, :blast_radius,
                            :attack_tactics, :attack_platforms, :loss_outcomes,
                            :mapping_run_id, :cve_id
                        )
                        ON CONFLICT (technique_id, tactic, item_id, framework_id) DO UPDATE SET
                            relevance_score = EXCLUDED.relevance_score,
                            confidence = EXCLUDED.confidence,
                            rationale = EXCLUDED.rationale,
                            tactic_risk_lens = EXCLUDED.tactic_risk_lens,
                            blast_radius = EXCLUDED.blast_radius,
                            attack_tactics = EXCLUDED.attack_tactics,
                            attack_platforms = EXCLUDED.attack_platforms,
                            loss_outcomes = EXCLUDED.loss_outcomes,
                            mapping_run_id = EXCLUDED.mapping_run_id,
                            cve_id = EXCLUDED.cve_id,
                            updated_at = NOW()
                    """)
        bs = max(1, int(batch_size))
        with get_security_intel_session("cve_attack") as session:
            for i in range(0, len(results), bs):
                chunk = results[i : i + bs]
                params = [
                    {
                        "technique_id": r["technique_id"],
                        "tactic": r["tactic"],
                        "item_id": r["item_id"],
                        "framework_id": r["framework_id"],
                        "relevance_score": r["relevance_score"],
                        "confidence": r["confidence"],
                        "rationale": r["rationale"],
                        "tactic_risk_lens": r.get("tactic_risk_lens", ""),
                        "blast_radius": r.get("blast_radius", "identity"),
                        "attack_tactics": r.get("attack_tactics", []),
                        "attack_platforms": r.get("attack_platforms", []),
                        "loss_outcomes": r.get("loss_outcomes", []),
                        "mapping_run_id": run_id,
                        "cve_id": cve_id,
                    }
                    for r in chunk
                ]
                session.execute(stmt, params)
        return len(results)
    except Exception as e:
        if "does not exist" not in str(e).lower():
            logger.warning(f"Failed to persist to attack_control_mappings_multi: {e}")
        return 0


def _resolve_tactic_to_valid_phase(
    technique_id: str,
    technique_name: str,
    requested_tactic: str,
    valid_tactics: List[str],
    cve_context: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    When requested_tactic is not in valid_tactics, use LLM to pick the best related
    kill chain phase from valid_tactics.
    """
    if not valid_tactics:
        return None
    if requested_tactic in valid_tactics:
        return requested_tactic

    from asteraskills.core.llm import get_llm
    from langchain_core.messages import SystemMessage, HumanMessage

    cve_hint = ""
    if cve_context and cve_context.get("description"):
        cve_hint = f"\nCVE context: {cve_context.get('description', '')[:300]}..."

    system = """You are a MITRE ATT&CK expert. Given an ATT&CK technique and a requested tactic that is NOT in the technique's kill chain phases, pick the SINGLE best-matching tactic from the valid list.

Return ONLY the tactic slug (e.g. defense-evasion, persistence) — no explanation, no markdown."""

    user = f"""Technique: {technique_id} ({technique_name})
Requested tactic (invalid): {requested_tactic}
Valid kill chain phases for this technique: {valid_tactics}
{cve_hint}

Which valid tactic best relates to the requested '{requested_tactic}'? Return only the tactic slug."""

    try:
        llm = get_llm(temperature=0.0)
        resp = llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
        content = (resp.content if hasattr(resp, "content") else str(resp)).strip().lower().replace(" ", "-")
        for v in valid_tactics:
            if v.lower() == content or content.endswith(v) or v in content:
                logger.info(f"Resolved ({technique_id}, {requested_tactic}) → {v} (LLM)")
                return v
        fallback = valid_tactics[0]
        logger.warning(f"LLM returned '{content}' not in {valid_tactics}; using {fallback}")
        return fallback
    except Exception as e:
        logger.warning(f"Tactic resolution failed: {e}; using first valid tactic")
        return valid_tactics[0]


def build_control_mapping_prompt_for_batch(
    technique_id: str,
    tactic: str,
    framework_id: str,
    top_k: int = 8,
    cve_id: Optional[str] = None,
    cve_context: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Build (system_prompt, user_prompt) for Stage 3 control mapping.
    Used by OpenAI Batch API. Runs local lookups (technique, tactic context, framework items).
    Uses retrieval fallbacks (broad vector, YAML); if still empty, uses LLM-only prompts (no longer returns None).
    """
    tid = technique_id.strip().upper()
    tactic_slug = tactic.strip().lower().replace(" ", "-")

    settings = get_settings()
    pg_dsn = settings.get_attack_db_dsn() if hasattr(settings, "get_attack_db_dsn") else None
    enricher = ATTACKEnrichmentTool(use_postgres=bool(pg_dsn), pg_dsn=pg_dsn)
    technique = enricher.get_technique(tid)

    valid_tactics = getattr(technique, "kill_chain_phases", None) or []
    if tactic_slug not in valid_tactics:
        resolved = _resolve_tactic_to_valid_phase(
            tid, technique.name, tactic_slug, valid_tactics, cve_context
        )
        if not resolved:
            return None
        tactic_slug = resolved

    ctx = _get_tactic_context(tid, tactic_slug)
    tactic_risk_lens = ctx.get("tactic_risk_lens", "")
    blast_radius = ctx.get("blast_radius", "identity")

    items = _get_framework_items_stage3(tactic_risk_lens, framework_id, tactic_slug, top_k)

    framework_name, control_id_label = _get_framework_metadata(framework_id)

    cve_section = ""
    if cve_id and cve_context:
        cve_section = f"\n=== CVE Context (for richer rationale) ===\nCVE: {cve_id}\n"
        if cve_context.get("description"):
            cve_section += f"Description: {cve_context['description'][:400]}...\n"
        if cve_context.get("affected_products"):
            cve_section += f"Affected: {', '.join(cve_context['affected_products'][:5])}\n"
        if cve_context.get("exploit_maturity"):
            cve_section += f"Exploit maturity: {cve_context['exploit_maturity']}\n"
        cve_section += "\n"

    if items:
        scenarios_json = json.dumps(items, indent=2)
        user_prompt = CONTROL_MAPPING_USER.format(
            technique_id=tid,
            technique_name=technique.name,
            tactics=", ".join(technique.tactics),
            platforms=", ".join(technique.platforms),
            description=technique.description[:800],
            mitigations=json.dumps(technique.mitigations)[:300],
            data_sources=", ".join(technique.data_sources)[:200],
            framework_name=framework_name,
            top_k=len(items),
            scenarios_json=scenarios_json,
        )
        system_prompt = CONTROL_MAPPING_SYSTEM.format(
            framework_name=framework_name,
            control_id_label=control_id_label,
        )
    else:
        user_prompt = CONTROL_MAPPING_USER_NO_CANDIDATES.format(
            technique_id=tid,
            technique_name=technique.name,
            tactics=", ".join(technique.tactics),
            platforms=", ".join(technique.platforms),
            description=technique.description[:800],
            mitigations=json.dumps(technique.mitigations)[:300],
            data_sources=", ".join(technique.data_sources)[:200],
            framework_name=framework_name,
            control_id_label=control_id_label,
            max_proposals=top_k,
        )
        system_prompt = CONTROL_MAPPING_SYSTEM_NO_CANDIDATES.format(
            framework_name=framework_name,
            control_id_label=control_id_label,
        )
    if cve_section:
        user_prompt = cve_section + user_prompt
    return {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "tactic_risk_lens": tactic_risk_lens,
        "blast_radius": blast_radius,
    }


def _execute_attack_control_map(
    technique_id: str,
    tactic: str,
    framework_id: str,
    top_k: int = 8,
    cve_id: Optional[str] = None,
    cve_context: Optional[Dict[str, Any]] = None,
    persist: bool = True,
) -> List[Dict[str, Any]]:
    """Execute AttackControlMappingTool."""
    from asteraskills.core.llm import get_llm

    tid = technique_id.strip().upper()
    tactic_slug = tactic.strip().lower().replace(" ", "-")

    # 1. Get technique
    settings = get_settings()
    pg_dsn = settings.get_attack_db_dsn() if hasattr(settings, "get_attack_db_dsn") else None
    enricher = ATTACKEnrichmentTool(use_postgres=bool(pg_dsn), pg_dsn=pg_dsn)
    technique = enricher.get_technique(tid)

    valid_tactics = getattr(technique, "kill_chain_phases", None) or []
    if tactic_slug not in valid_tactics:
        resolved = _resolve_tactic_to_valid_phase(
            tid, technique.name, tactic_slug, valid_tactics, cve_context
        )
        if not resolved:
            return []
        tactic_slug = resolved

    # 2. Get tactic context
    ctx = _get_tactic_context(tid, tactic_slug)
    tactic_risk_lens = ctx.get("tactic_risk_lens", "")
    blast_radius = ctx.get("blast_radius", "identity")

    # 3. Get framework items (Stage 3 fallbacks + optional LLM-only)
    items = _get_framework_items_stage3(tactic_risk_lens, framework_id, tactic_slug, top_k)

    # 4. Framework metadata
    framework_name, control_id_label = _get_framework_metadata(framework_id)

    # 5. LLM mapping
    cve_section = ""
    if cve_id and cve_context:
        cve_section = f"\n=== CVE Context (for richer rationale) ===\nCVE: {cve_id}\n"
        if cve_context.get("description"):
            cve_section += f"Description: {cve_context['description'][:400]}...\n"
        if cve_context.get("affected_products"):
            cve_section += f"Affected: {', '.join(cve_context['affected_products'][:5])}\n"
        if cve_context.get("exploit_maturity"):
            cve_section += f"Exploit maturity: {cve_context['exploit_maturity']}\n"
        cve_section += "\n"

    if items:
        scenarios_json = json.dumps(items, indent=2)
        user_prompt = CONTROL_MAPPING_USER.format(
            technique_id=tid,
            technique_name=technique.name,
            tactics=", ".join(technique.tactics),
            platforms=", ".join(technique.platforms),
            description=technique.description[:800],
            mitigations=json.dumps(technique.mitigations)[:300],
            data_sources=", ".join(technique.data_sources)[:200],
            framework_name=framework_name,
            top_k=len(items),
            scenarios_json=scenarios_json,
        )
        system_prompt = CONTROL_MAPPING_SYSTEM.format(
            framework_name=framework_name,
            control_id_label=control_id_label,
        )
    else:
        user_prompt = CONTROL_MAPPING_USER_NO_CANDIDATES.format(
            technique_id=tid,
            technique_name=technique.name,
            tactics=", ".join(technique.tactics),
            platforms=", ".join(technique.platforms),
            description=technique.description[:800],
            mitigations=json.dumps(technique.mitigations)[:300],
            data_sources=", ".join(technique.data_sources)[:200],
            framework_name=framework_name,
            control_id_label=control_id_label,
            max_proposals=top_k,
        )
        system_prompt = CONTROL_MAPPING_SYSTEM_NO_CANDIDATES.format(
            framework_name=framework_name,
            control_id_label=control_id_label,
        )
    if cve_section:
        user_prompt = cve_section + user_prompt
    from langchain_core.messages import SystemMessage, HumanMessage
    llm = get_llm(temperature=0.2)
    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt),
    ])
    content = response.content if hasattr(response, "content") else str(response)
    try:
        mappings = _extract_json(content)
        if not isinstance(mappings, list):
            mappings = []
    except json.JSONDecodeError:
        logger.warning(f"LLM mapping returned invalid JSON: {content[:200]}")
        mappings = []

    # 6. LLM validation
    technique_summary = f"{tid} {technique.name}: {tactic_risk_lens[:200]}..."
    validation_user = VALIDATION_USER.format(
        framework_name=framework_name,
        technique_summary=technique_summary,
        raw_mappings_json=json.dumps(mappings, indent=2),
    )
    validation_system = VALIDATION_SYSTEM.format(framework_name=framework_name)
    val_response = llm.invoke([
        SystemMessage(content=validation_system),
        HumanMessage(content=validation_user),
    ])
    val_content = val_response.content if hasattr(val_response, "content") else str(val_response)
    try:
        val_data = _extract_json(val_content)
        corrected = val_data.get("corrected_mappings", mappings)
    except json.JSONDecodeError:
        corrected = mappings

    # 7. Build result list (attach Stage-3 item text so downstream reports get titles / definitions)
    def _meta_for_item(iid: str) -> Dict[str, str]:
        for it in items or []:
            cand = (it.get("item_id") or it.get("scenario_id") or "").strip()
            if cand and cand.casefold() == (iid or "").strip().casefold():
                return {
                    "title": (it.get("title") or "").strip(),
                    "control_objective": (it.get("control_objective") or "").strip(),
                    "risk_description": (it.get("risk_description") or "").strip(),
                    "trigger": (it.get("trigger") or "").strip(),
                }
        return {"title": "", "control_objective": "", "risk_description": "", "trigger": ""}

    results = []
    for m in corrected:
        item_id = m.get("scenario_id") or m.get("item_id") or ""
        if not item_id:
            continue
        extra = _meta_for_item(item_id)
        results.append({
            "technique_id": tid,
            "tactic": tactic_slug,
            "item_id": item_id,
            "framework_id": framework_id,
            "relevance_score": float(m.get("relevance_score", 0.5)),
            "confidence": m.get("confidence", "medium"),
            "rationale": m.get("rationale", ""),
            "tactic_risk_lens": tactic_risk_lens,
            "blast_radius": m.get("blast_radius") or blast_radius,
            "control_family": m.get("control_family", ""),
            "attack_tactics": m.get("attack_tactics", technique.tactics),
            "attack_platforms": m.get("attack_platforms", technique.platforms),
            "loss_outcomes": m.get("loss_outcomes", []),
            "title": extra.get("title") or m.get("title", ""),
            "control_objective": extra.get("control_objective") or m.get("control_objective", ""),
            "risk_description": extra.get("risk_description") or m.get("risk_description", ""),
            "trigger": extra.get("trigger") or m.get("trigger", ""),
        })

    # 8. Persist to attack_control_mappings_multi when requested (CVE pipeline)
    if persist and results:
        _persist_control_mappings_multi(results, cve_id=cve_id)

    return results


def create_attack_control_mapping_tool() -> StructuredTool:
    """Create LangChain tool for ATT&CK → control mapping."""
    return StructuredTool.from_function(
        func=_execute_attack_control_map,
        name="attack_control_map",
        description="Map an ATT&CK technique (under a specific tactic) to framework controls. Returns relevance scores, confidence, rationale. Use kill_chain_phases slug for tactic.",
        args_schema=AttackControlMappingInput,
    )
