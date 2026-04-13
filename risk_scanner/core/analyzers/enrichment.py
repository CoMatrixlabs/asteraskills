"""
Enrichment analyzer — CVE/CWE/Policy → ATT&CK → framework controls.

Reuses asteraskills tools directly (local mode) or delegates to the licensed
intelligence server (remote mode via PackClient).

Enrichment chain per finding:
  0. apply_kev_override() — KEV catalog check + severity override + ``finding.kev_context``
     (structured KEV signals for PROMPT-11 / reporting). Runs BEFORE ATT&CK enrichment
     so the mapper receives a KEV-adjusted severity and ransomware context when present.
  1. enrich_attack()  — domain → ATT&CK techniques (PROMPT-07/08/09)
  2. enrich_controls() — techniques → framework controls (PROMPT-10)
  3. contextualize_severity() — final severity contextualization (PROMPT-11),
     starting from the KEV-adjusted severity as baseline.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from risk_scanner.core.models import (
    AttackEnrichment,
    ControlEnrichment,
    Domain,
    Finding,
    KevEntry,
    SatisfactionStatus,
    Severity,
)
from risk_scanner.core.pack_client import PackClient
from risk_scanner.core.prompts import format_prompt

log = logging.getLogger(__name__)

_KILL_CHAIN_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


class EnrichmentAnalyzer:
    """Enrich pre-detected findings with ATT&CK techniques and control gaps."""

    def enrich(self, findings: List[Finding]) -> List[Finding]:
        """Enrich each finding in-place. Returns the same list with enrichment populated."""
        enriched = []
        for finding in findings:
            try:
                enriched.append(self._enrich_one(finding))
            except Exception as exc:
                log.warning("Enrichment failed for %s: %s", finding.taxonomy_code, exc)
                enriched.append(finding)
        return enriched

    def __init__(
        self,
        pack_client: "PackClient",
        llm: Optional[object],
        frameworks: Optional[List[str]] = None,
        kev_client: Optional[object] = None,
        enrich_cpe: bool = True,
        max_related_cves: int = 0,
    ) -> None:
        self.pack_client = pack_client
        self.llm = llm
        self.frameworks = ["cis-8", "nist-800-53"] if frameworks is None else list(frameworks)
        self.kev_client = kev_client
        self.enrich_cpe = enrich_cpe
        self.max_related_cves = max_related_cves

    def _enrich_one(self, finding: Finding) -> Finding:
        # Step 0 (KEV): deterministic catalog check — CVE domain only, runs first
        # so ATT&CK enrichment receives a KEV-adjusted severity and ransomware context.
        if finding.domain == Domain.CVE and self.kev_client is not None:
            finding = self._apply_kev_override(finding)

        # Step 0.5 (CPE): Stage 1.5 — resolve affected_products to canonical CPE URIs
        if finding.domain == Domain.CVE and self.enrich_cpe:
            finding = self._enrich_cpe(finding)

        # Step 1: ATT&CK enrichment
        attack_chain = self._enrich_attack(finding)
        finding.attack_chain = attack_chain

        # Step 2: control enrichment (per technique)
        if attack_chain:
            control_gaps = self._enrich_controls(attack_chain, finding)
            finding.control_gaps = control_gaps

        # Step 3: severity contextualization
        finding = self._contextualize_severity(finding)

        # Step 4: generate summary + remediation narrative
        finding = self._generate_narrative(finding)

        # Step 5 (optional): related CVE expansion
        if self.max_related_cves > 0 and finding.domain == Domain.CVE and finding.attack_chain:
            finding = self._enrich_related_cves(finding)

        return finding

    # ------------------------------------------------------------------
    # Step 0.5: CPE enrichment (Stage 1.5)
    # ------------------------------------------------------------------

    def _enrich_cpe(self, finding: Finding) -> Finding:
        """Resolve affected_products to canonical CPE URIs (Stage 1.5).

        Must be called AFTER cve_detail is populated. If cve_detail is absent or
        lacks affected_products, we fetch it first via _execute_cve_enrich so this
        step is safe to call regardless of ordering.
        """
        # Ensure we have CVE detail (affected_products) before attempting CPE resolution
        detail = finding.cve_detail or {}
        affected = detail.get("affected_products") or []
        if not affected:
            # Fetch NVD detail now so we have affected_products to work with
            try:
                from asteraskills.tools.cve_enrichment import _execute_cve_enrich
                fetched = _execute_cve_enrich(finding.taxonomy_code)
                if fetched:
                    finding.cve_detail = fetched
                    detail = fetched
                    affected = detail.get("affected_products") or []
            except Exception as exc:
                log.debug("CVE detail pre-fetch for CPE enrich (%s): %s", finding.taxonomy_code, exc)

        finding.cpe_enrichment_attempted = True

        if not affected:
            log.info(
                "CPE enrich %s: no affected_products in NVD data — "
                "CPE registry may not be populated; run cpe_registry_cli first",
                finding.taxonomy_code,
            )
            return finding

        try:
            from asteraskills.tools.cpe_enrichment import _execute_cpe_enrich
            result = _execute_cpe_enrich(finding.taxonomy_code, affected)
            matches = result.get("cpe_matches", [])
            method = result.get("resolution_method", "empty")
            if matches:
                finding.cpe_matches = matches
                if not finding.source_cpe_uri:
                    finding.source_cpe_uri = matches[0].get("cpe_uri", "")
                if finding.cve_detail is not None:
                    finding.cve_detail["cpe_matches"] = matches
                log.info(
                    "CPE enrich %s: %d match(es) via %s",
                    finding.taxonomy_code, len(matches), method,
                )
            else:
                log.info(
                    "CPE enrich %s: no matches found (method=%s) — "
                    "CPE registry may not be populated; run cpe_registry_cli first",
                    finding.taxonomy_code, method,
                )
        except Exception as exc:
            log.debug("CPE enrich for %s: %s", finding.taxonomy_code, exc)
        return finding

    # ------------------------------------------------------------------
    # Step 5: Related CVE expansion (optional)
    # ------------------------------------------------------------------

    def _enrich_related_cves(self, finding: Finding) -> Finding:
        """Append ranked related CVEs sharing ATT&CK techniques with this finding."""
        technique_ids = [a.technique_id for a in finding.attack_chain if a.technique_id]
        if not technique_ids:
            return finding
        try:
            from asteraskills.tools.related_cves_skill import _execute_related_cves
            query = technique_ids[0] if len(technique_ids) == 1 else " ".join(technique_ids[:3])
            result = _execute_related_cves(
                query=query,
                max_results=self.max_related_cves,
                min_cvss=0.0,
            )
            ranked = result.get("results", [])
            # Exclude the finding itself
            finding.related_cves = [
                r for r in ranked if r.get("cve_id") != finding.taxonomy_code
            ][: self.max_related_cves]
        except Exception as exc:
            log.debug("Related CVE expansion for %s: %s", finding.taxonomy_code, exc)
        return finding

    # ------------------------------------------------------------------
    # Step 1: ATT&CK enrichment
    # ------------------------------------------------------------------

    def _enrich_attack(self, finding: Finding) -> List[AttackEnrichment]:
        domain = finding.domain

        if domain == Domain.CVE:
            return self._enrich_cve_attack(finding)
        elif domain == Domain.CWE:
            return self._enrich_cwe_attack(finding)
        elif domain == Domain.POLICY:
            return self._enrich_policy_attack(finding)
        elif domain == Domain.ATTACK:
            # Already a TTP — convert taxonomy_code directly
            return [AttackEnrichment(
                technique_id=finding.taxonomy_code,
                technique_name=finding.summary or finding.taxonomy_code,
                tactic="unknown",
                kill_chain_pos=1,
                confidence=finding.confidence,
                rationale="Direct ATT&CK finding — no enrichment needed.",
            )]
        return []

    def _enrich_cve_attack(self, finding: Finding) -> List[AttackEnrichment]:
        """CVE → ATT&CK via asteraskills cve_attack_mapper or server index."""
        cve_id = finding.taxonomy_code
        cve_detail: Dict[str, Any] = finding.cve_detail or {}

        # If sbom_cve_context pre-seeded technique IDs, convert them directly
        pre_seeded = cve_detail.get("pre_seeded_techniques", [])
        if pre_seeded:
            return [
                AttackEnrichment(
                    technique_id=tid,
                    technique_name=tid,
                    tactic="unknown",
                    kill_chain_pos=5,
                    confidence=0.85,
                    rationale="Pre-seeded from sbom_cve_context ATT&CK hydration",
                )
                for tid in pre_seeded
            ]

        # Try to get CVE detail from asteraskills
        if not cve_detail:
            try:
                from asteraskills.tools.cve_enrichment import _execute_cve_enrich
                detail = _execute_cve_enrich(cve_id)
                if detail:
                    cve_detail = detail
                    finding.cve_detail = detail
            except Exception as exc:
                log.debug("CVE enrich for %s: %s", cve_id, exc)

        # Get retrieved mappings from pack_client
        retrieved = self.pack_client.retrieve_attack_mappings(
            source_domain="cve",
            taxonomy_code=cve_id,
            metadata={"cve_detail": cve_detail},
        )

        # If we have mappings, use them directly
        if retrieved:
            return _mappings_to_attack_enrichments(retrieved)

        # Otherwise call asteraskills mapper
        try:
            from asteraskills.tools.cve_attack_mapper import _execute_cve_to_attack_map
            mappings = _execute_cve_to_attack_map(cve_id, cve_detail or {})
            if mappings:
                return [
                    AttackEnrichment(
                        technique_id=m.get("technique_id", ""),
                        technique_name=m.get("technique_name", m.get("technique_id", "")),
                        tactic=m.get("tactic", "unknown"),
                        kill_chain_pos=_tactic_to_pos(m.get("tactic", "")),
                        confidence=_conf_str_to_float(m.get("confidence", "medium")),
                        rationale=m.get("rationale", f"CWE crosswalk mapping for {cve_id}"),
                    )
                    for m in mappings if m.get("technique_id")
                ]
        except Exception as exc:
            log.debug("CVE attack map for %s: %s", cve_id, exc)

        # Fall back to LLM prompt if available
        if self.llm and cve_detail:
            return self._llm_cve_attack(finding, cve_detail, retrieved)
        return []

    def _enrich_cwe_attack(self, finding: Finding) -> List[AttackEnrichment]:
        """CWE → ATT&CK via asteraskills cwe_to_attack_intel."""
        cwe_id = finding.taxonomy_code

        retrieved = self.pack_client.retrieve_attack_mappings(
            source_domain="cwe",
            taxonomy_code=cwe_id,
            metadata={},
        )
        if retrieved:
            return _mappings_to_attack_enrichments(retrieved)

        try:
            from asteraskills.tools.cwe_capec_cis_tools import create_cwe_to_attack_intel_tool
            tool = create_cwe_to_attack_intel_tool()
            result = tool.invoke({"cwe_id": cwe_id})
            if isinstance(result, list):
                return [
                    AttackEnrichment(
                        technique_id=r.get("technique_id", ""),
                        technique_name=r.get("technique_name", r.get("technique_id", "")),
                        tactic=r.get("tactic", "unknown"),
                        kill_chain_pos=_tactic_to_pos(r.get("tactic", "")),
                        confidence=0.8,
                        rationale=f"CWE→ATT&CK mapping for {cwe_id}",
                    )
                    for r in result if r.get("technique_id")
                ]
        except Exception as exc:
            log.debug("CWE attack map for %s: %s", cwe_id, exc)

        # LLM fallback
        if self.llm:
            return self._llm_cwe_attack(finding)
        return []

    def _enrich_policy_attack(self, finding: Finding) -> List[AttackEnrichment]:
        """Policy/misconfiguration → ATT&CK via static rules + LLM."""
        policy_id = finding.taxonomy_code

        # Static policy → technique mapping
        _STATIC_POLICY_MAP: Dict[str, List[Dict[str, Any]]] = {
            "AWS-S3-001": [{"technique_id": "T1530", "technique_name": "Data from Cloud Storage Object",
                            "tactic": "collection", "confidence": 0.95}],
            "AWS-S3-002": [{"technique_id": "T1530", "technique_name": "Data from Cloud Storage Object",
                            "tactic": "collection", "confidence": 0.7}],
            "AWS-SG-001": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
                            "tactic": "initial-access", "confidence": 0.9}],
            "AWS-SG-002": [{"technique_id": "T1021.004", "technique_name": "Remote Services: SSH",
                            "tactic": "lateral-movement", "confidence": 0.85}],
            "AWS-IAM-001": [{"technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts",
                             "tactic": "privilege-escalation", "confidence": 0.9},
                            {"technique_id": "T1548", "technique_name": "Abuse Elevation Control Mechanism",
                             "tactic": "privilege-escalation", "confidence": 0.8}],
            "K8S-001": [{"technique_id": "T1611", "technique_name": "Escape to Host",
                         "tactic": "privilege-escalation", "confidence": 0.8}],
        }
        static = _STATIC_POLICY_MAP.get(policy_id, [])
        if static:
            return [
                AttackEnrichment(
                    technique_id=m["technique_id"],
                    technique_name=m["technique_name"],
                    tactic=m["tactic"],
                    kill_chain_pos=_tactic_to_pos(m["tactic"]),
                    confidence=m.get("confidence", 0.8),
                    rationale=f"Static policy→technique mapping for {policy_id}",
                )
                for m in static
            ]

        if self.llm:
            return self._llm_policy_attack(finding)
        return []

    # ------------------------------------------------------------------
    # Step 0: KEV override (CVE domain only)
    # ------------------------------------------------------------------

    def _apply_kev_override(self, finding: Finding) -> Finding:
        """Look up the CVE in the CISA KEV catalog and apply severity override.

        Override hierarchy (applied in order, first match wins):
          1. Ransomware campaign use → CRITICAL (unconditional, never downgraded)
          2. Non-ransomware KEV, LLM available → PROMPT-17 determines final severity
          3. Non-ransomware KEV, no LLM → static HIGH minimum
        """
        try:
            kev: KevEntry = self.kev_client.lookup(finding.taxonomy_code)
        except Exception as exc:
            log.warning("KEV lookup failed for %s: %s", finding.taxonomy_code, exc)
            finding.kev_context = None
            return finding

        finding.kev_entry = kev

        if not kev.in_kev:
            finding.kev_context = None
            return finding   # Not in catalog — no override

        # Structured context for exports, LLM prompts, and PROMPT-11 severity signals
        finding.kev_context = _build_kev_context(kev, finding.taxonomy_code)

        # Record original severity for audit trail
        kev.pre_kev_severity = finding.severity.value

        # --- Rule 1: Ransomware → unconditional CRITICAL ---
        if kev.ransomware_campaign_use:
            if finding.severity != Severity.CRITICAL:
                kev.severity_was_upgraded = True
                finding.severity = Severity.CRITICAL
                group_note = f" (group: {kev.ransomware_group})" if kev.ransomware_group else ""
                finding.severity_rationale += (
                    f" [KEV CRITICAL OVERRIDE] {finding.taxonomy_code} is in the CISA KEV catalog"
                    f" with confirmed ransomware campaign use{group_note}."
                    " Severity upgraded to CRITICAL unconditionally — ransomware association"
                    " indicates active weaponization by financially motivated threat actors."
                )
            else:
                # Already CRITICAL — just add KEV context to rationale
                finding.severity_rationale += (
                    f" [KEV CONFIRMED] {finding.taxonomy_code} is in the CISA KEV catalog"
                    f" with ransomware campaign use{(f' by {kev.ransomware_group}') if kev.ransomware_group else ''}."
                )
            return finding

        # --- Rule 2/3: Non-ransomware KEV ---
        if self.llm:
            finding = self._llm_kev_severity(finding, kev)
        else:
            # Static rule: KEV is always at least HIGH
            if finding.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM):
                kev.severity_was_upgraded = True
                finding.severity = Severity.HIGH
                finding.severity_rationale += (
                    f" [KEV OVERRIDE] {finding.taxonomy_code} is in the CISA KEV catalog"
                    " (confirmed exploitation in the wild). Upgraded to HIGH — KEV entries"
                    " are never below HIGH regardless of CVSS score."
                )

        return finding

    def _llm_kev_severity(self, finding: Finding, kev: KevEntry) -> Finding:
        """Use PROMPT-17 to determine final KEV-adjusted severity."""
        from datetime import date as _date
        try:
            kev_json = kev.model_dump(mode="json", exclude={"severity_was_upgraded", "pre_kev_severity"})
            prompt = format_prompt(
                "PROMPT-17",
                kev_entry_json=json.dumps(kev_json, default=str, indent=2),
                cve_id=finding.taxonomy_code,
                cvss_score=str(finding.confidence * 10),  # proxy — ideally pass real CVSS
                internet_facing="unknown",
                environment="production",
                initial_severity=finding.severity.value,
                current_date=str(_date.today()),
            )
            result = _invoke_llm(self.llm, prompt)
            new_sev_str = result.get("final_severity", "").upper()
            if new_sev_str in (s.value for s in Severity):
                new_sev = Severity(new_sev_str)
                if new_sev != finding.severity:
                    kev.severity_was_upgraded = True
                finding.severity = new_sev
                finding.severity_rationale += f" [KEV] {result.get('severity_rationale', '')}"

                # Surface BOD 22-01 overdue flag in rationale
                if result.get("is_overdue"):
                    days = result.get("days_overdue", "")
                    finding.severity_rationale += (
                        f" BOD 22-01 remediation deadline is {days} day(s) overdue."
                    )
                    if result.get("escalation_note"):
                        finding.summary = f"ESCALATION: {result['escalation_note']}"
        except Exception as exc:
            log.debug("PROMPT-17 LLM failed for %s: %s", finding.taxonomy_code, exc)
            # Static fallback
            if finding.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM):
                kev.severity_was_upgraded = True
                finding.severity = Severity.HIGH
        return finding

    # ------------------------------------------------------------------
    # Step 2: Control enrichment
    # ------------------------------------------------------------------

    def _enrich_controls(
        self,
        attack_chain: List[AttackEnrichment],
        finding: Finding,
    ) -> List[ControlEnrichment]:
        technique_ids = list({a.technique_id for a in attack_chain if a.technique_id})
        if not technique_ids:
            return []
        if not self.frameworks:
            return []

        # Try pack_client (remote or local asteraskills delegate)
        retrieved = self.pack_client.retrieve_control_mappings(technique_ids, self.frameworks)

        controls: List[ControlEnrichment] = []
        if retrieved:
            for m in retrieved:
                cid = m.get("control_id", "")
                cname = (
                    (m.get("control_name") or "").strip()
                    or (m.get("title") or "").strip()
                    or (m.get("name") or "").strip()
                    or cid
                )
                gap = (m.get("gap_narrative") or m.get("rationale") or "").strip()
                rem = (
                    (m.get("remediation") or "").strip()
                    or (m.get("blast_radius") or "").strip()
                    or "See framework documentation for remediation guidance."
                )
                controls.append(ControlEnrichment(
                    control_id=cid,
                    framework=m.get("framework", ""),
                    framework_version=_framework_version(m.get("framework", "")),
                    control_name=cname,
                    satisfaction=SatisfactionStatus.UNKNOWN,
                    gap_narrative=gap or None,
                    remediation=rem,
                    priority=_priority_from_technique(attack_chain),
                ))
            return controls

        # Direct asteraskills tool call
        for technique_id in technique_ids[:3]:  # limit to 3 to avoid API flood
            for framework in self.frameworks:
                try:
                    from asteraskills.tools.attack_control_mapping import _execute_attack_control_map
                    from risk_scanner.core.pack_client import _normalize_framework_id
                    fw_id = _normalize_framework_id(framework)
                    # Get tactic from attack chain for this technique
                    tactic = next(
                        (a.tactic for a in attack_chain if a.technique_id == technique_id),
                        ""
                    )
                    mappings = _execute_attack_control_map(
                        technique_id=technique_id,
                        tactic=tactic,
                        framework_id=fw_id,
                        top_k=5,
                        persist=False,
                    )
                    for m in (mappings or []):
                        iid = m.get("item_id", "")
                        title = (
                            (m.get("title") or "").strip()
                            or (m.get("control_objective") or "").strip()
                            or iid
                        )
                        controls.append(ControlEnrichment(
                            control_id=iid,
                            framework=framework,
                            framework_version=_framework_version(framework),
                            control_name=title,
                            control_type=_infer_control_type(m),
                            satisfaction=SatisfactionStatus.UNKNOWN,
                            gap_narrative=m.get("rationale", ""),
                            remediation=(m.get("blast_radius") or "Review and implement this control."),
                            priority=_priority_from_technique(attack_chain),
                        ))
                except Exception as exc:
                    log.debug("Control enrichment %s/%s: %s", technique_id, framework, exc)

        # LLM fallback for control enrichment
        if not controls and self.llm:
            controls = self._llm_controls(attack_chain, finding)

        return controls

    # ------------------------------------------------------------------
    # Step 3: Severity contextualization
    # ------------------------------------------------------------------

    def _contextualize_severity(self, finding: Finding) -> Finding:
        """Adjust severity based on ATT&CK enrichment and control gaps."""
        # PROMPT-11: KEV BOD 22-01 overdue signal (CVE enrichment; complements Step 0 KEV override)
        ctx = finding.kev_context
        if ctx and ctx.get("overdue"):
            finding.severity_rationale += (
                " [PROMPT-11] CISA KEV remediation due date has passed (BOD 22-01); "
                "prioritize patching and compensating controls."
            )

        if not finding.attack_chain and not finding.control_gaps:
            return finding

        # Upgrade to CRITICAL: exfiltration/impact technique + missing preventive control
        has_impact = any(
            a.tactic in ("exfiltration", "impact") for a in finding.attack_chain
        )
        has_missing_preventive = any(
            c.satisfaction == SatisfactionStatus.MISSING and c.control_type == "preventive"
            for c in finding.control_gaps
        )
        all_satisfied = all(
            c.satisfaction == SatisfactionStatus.SATISFIED
            for c in finding.control_gaps
        ) if finding.control_gaps else False

        initial = finding.severity
        if has_impact and has_missing_preventive and finding.severity != Severity.CRITICAL:
            finding.severity = Severity.CRITICAL
            finding.severity_rationale += (
                " Upgraded to CRITICAL: exfiltration/impact technique enabled with missing preventive control."
            )
        elif all_satisfied and finding.severity in (Severity.HIGH, Severity.MEDIUM):
            # Downgrade if all controls are satisfied
            order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            idx = order.index(finding.severity)
            finding.severity = order[max(0, idx - 1)]
            finding.severity_rationale += " Downgraded: all mapped controls are satisfied."

        return finding

    # ------------------------------------------------------------------
    # Narrative generation
    # ------------------------------------------------------------------

    def _generate_narrative(self, finding: Finding) -> Finding:
        """Generate summary and remediation narrative using LLM or static template."""
        if not finding.summary:
            finding.summary = _static_summary(finding)
        if not finding.remediation:
            finding.remediation = _static_remediation(finding)
        return finding

    # ------------------------------------------------------------------
    # LLM prompt calls (used when pack_client.local_mode and llm available)
    # ------------------------------------------------------------------

    def _llm_cve_attack(
        self,
        finding: Finding,
        cve_detail: Dict[str, Any],
        retrieved: List[Dict[str, Any]],
    ) -> List[AttackEnrichment]:
        try:
            prompt = format_prompt(
                "PROMPT-07",
                cve_id=finding.taxonomy_code,
                cvss_vector=cve_detail.get("cvss_vector", "unknown"),
                cvss_score=cve_detail.get("cvss_score", "unknown"),
                component=finding.evidence.matched_pattern or "unknown",
                deployment_context=f"environment: production, file: {finding.evidence.file_path}",
                retrieved_mappings=json.dumps(retrieved[:5], indent=2),
            )
            result = _invoke_llm(self.llm, prompt)
            return _parse_attack_enrichments(result.get("enabled_techniques", []))
        except Exception as exc:
            log.debug("LLM CVE attack enrichment: %s", exc)
            return []

    def _llm_cwe_attack(self, finding: Finding) -> List[AttackEnrichment]:
        try:
            ev = finding.evidence
            prompt = format_prompt(
                "PROMPT-08",
                cwe_id=finding.taxonomy_code,
                cwe_name=finding.summary or finding.taxonomy_code,
                source_type=ev.matched_rule_id or "unknown",
                sink_type=ev.matched_pattern or "unknown",
                sink_expression=ev.snippet or "",
                cross_file="false",
                retrieved_mappings="[]",
            )
            result = _invoke_llm(self.llm, prompt)
            return _parse_attack_enrichments(result.get("enabled_techniques", []))
        except Exception as exc:
            log.debug("LLM CWE attack enrichment: %s", exc)
            return []

    def _llm_policy_attack(self, finding: Finding) -> List[AttackEnrichment]:
        try:
            prompt = format_prompt(
                "PROMPT-09",
                policy_findings=json.dumps([{"policy_id": finding.taxonomy_code,
                                             "misconfiguration": finding.severity_rationale}], indent=2),
                cloud_provider="aws",
                environment="production",
                internet_exposed="unknown",
                retrieved_mappings="[]",
            )
            result = _invoke_llm(self.llm, prompt)
            enrichments = []
            for enr in result.get("enrichments", []):
                enrichments.extend(_parse_attack_enrichments(enr.get("enabled_techniques", [])))
            return enrichments
        except Exception as exc:
            log.debug("LLM policy attack enrichment: %s", exc)
            return []

    def _llm_controls(
        self,
        attack_chain: List[AttackEnrichment],
        finding: Finding,
    ) -> List[ControlEnrichment]:
        try:
            techniques_json = json.dumps([
                {"technique_id": a.technique_id, "technique_name": a.technique_name,
                 "tactic": a.tactic, "kill_chain_pos": a.kill_chain_pos}
                for a in attack_chain
            ], indent=2)
            prompt = format_prompt(
                "PROMPT-10",
                licensed_frameworks=", ".join(self.frameworks),
                techniques=techniques_json,
                environment="production",
                known_controls="none specified",
                evidence_context="none",
                retrieved_mappings="[]",
            )
            result = _invoke_llm(self.llm, prompt)
            controls = []
            for mapping in result.get("control_mappings", []):
                for ctrl in mapping.get("controls", []):
                    controls.append(ControlEnrichment(
                        control_id=ctrl.get("control_id", ""),
                        framework=ctrl.get("framework", ""),
                        framework_version=ctrl.get("framework_version", ""),
                        control_name=ctrl.get("control_name", ""),
                        control_type=ctrl.get("control_type"),
                        satisfaction=SatisfactionStatus(ctrl.get("satisfaction", "unknown")),
                        gap_narrative=ctrl.get("gap_narrative"),
                        remediation=ctrl.get("remediation", ""),
                        priority=ctrl.get("priority"),
                    ))
            return controls
        except Exception as exc:
            log.debug("LLM control enrichment: %s", exc)
            return []


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _build_kev_context(kev: KevEntry, cve_id: str) -> Dict[str, Any]:
    """Build a stable dict of KEV catalog signals for CVE enrichment (PROMPT-11 / reporting)."""
    da = kev.kev_date_added
    dd = kev.kev_due_date
    dud = kev.days_until_due
    overdue = dud is not None and dud < 0
    ransomware = bool(kev.ransomware_campaign_use)
    return {
        "in_kev": True,
        "cve_id": cve_id,
        "date_added": da.isoformat() if da else None,
        "due_date": dd.isoformat() if dd else None,
        "days_until_due": dud,
        "overdue": overdue,
        "ransomware_campaign": ransomware,
        "ransomware_group": kev.ransomware_group,
        "required_action": kev.required_action,
        "severity_override_reason": (
            "KEV + active ransomware campaign"
            if ransomware
            else "Active exploitation confirmed by CISA KEV"
        ),
    }


def _invoke_llm(llm: object, prompt: str) -> Dict[str, Any]:
    from langchain_core.messages import HumanMessage
    resp = llm.invoke([HumanMessage(content=prompt)])  # type: ignore[union-attr]
    raw = resp.content if hasattr(resp, "content") else str(resp)
    import re
    # Strip markdown code fences if present
    raw = re.sub(r'^```(?:json)?\n?', '', raw.strip(), flags=re.MULTILINE)
    raw = re.sub(r'\n?```$', '', raw.strip(), flags=re.MULTILINE)
    return json.loads(raw)


def _mappings_to_attack_enrichments(retrieved: List[Dict[str, Any]]) -> List[AttackEnrichment]:
    result = []
    for m in retrieved:
        tid = m.get("technique_id", "")
        if not tid:
            continue
        result.append(AttackEnrichment(
            technique_id=tid,
            technique_name=m.get("technique_name", tid),
            tactic=m.get("tactic", "unknown"),
            kill_chain_pos=_tactic_to_pos(m.get("tactic", "")),
            confidence=float(m.get("similarity_score", 0.7)),
            rationale=f"Retrieved from pack index (type: {m.get('mapping_type', 'inferred')})",
        ))
    return result


def _parse_attack_enrichments(items: List[Dict[str, Any]]) -> List[AttackEnrichment]:
    result = []
    for item in items:
        tid = item.get("technique_id", "")
        if not tid:
            continue
        result.append(AttackEnrichment(
            technique_id=tid,
            technique_name=item.get("technique_name", tid),
            tactic=item.get("tactic", "unknown"),
            tactic_id=item.get("tactic_id"),
            kill_chain_pos=item.get("kill_chain_pos") or _tactic_to_pos(item.get("tactic", "")),
            confidence=float(item.get("confidence", 0.7)),
            rationale=item.get("rationale", "LLM enrichment"),
        ))
    return result


def _tactic_to_pos(tactic: str) -> int:
    tactic = tactic.lower().replace(" ", "-")
    try:
        return _KILL_CHAIN_ORDER.index(tactic) + 1
    except ValueError:
        return 5  # default: mid-chain


def _conf_str_to_float(conf: str) -> float:
    return {"high": 0.9, "medium": 0.7, "low": 0.5}.get(conf.lower(), 0.7)


def _framework_version(framework: str) -> str:
    return {
        "cis-8": "8.1", "nist-800-53": "Rev5", "soc2": "2017", "iso27001": "2022",
        "cis_v8_1": "8.1", "nist_800_53r5": "Rev5",
    }.get(framework, "latest")


def _infer_control_type(mapping: Dict[str, Any]) -> Optional[str]:
    rationale = (mapping.get("rationale") or "").lower()
    if any(w in rationale for w in ("prevent", "block", "deny", "restrict")):
        return "preventive"
    if any(w in rationale for w in ("detect", "monitor", "log", "alert")):
        return "detective"
    return "preventive"  # default


def _priority_from_technique(attack_chain: List[AttackEnrichment]) -> str:
    min_pos = min((a.kill_chain_pos for a in attack_chain), default=5)
    if min_pos <= 2:
        return "immediate"
    if min_pos <= 6:
        return "30-days"
    return "90-days"


def _static_summary(finding: Finding) -> str:
    code = finding.taxonomy_code
    sev = finding.severity.value
    fp = finding.evidence.file_path or "unknown"
    if finding.domain == Domain.CVE:
        detail = finding.cve_detail or {}
        prods = detail.get("affected_products") or []
        if prods:
            plist = ", ".join(str(p) for p in prods[:4])
            return f"{code} ({sev}) — affected: {plist}"
        if finding.evidence.file_path:
            return f"{code} ({sev}) affects component at {fp}"
        return f"{code} ({sev}) — CVE enrichment (no artifact path; see CVE intelligence table)"
    if finding.domain == Domain.CWE:
        return f"{code} ({sev}): taint flow detected in {fp}"
    if finding.domain == Domain.POLICY:
        return f"Policy {code} ({sev}): misconfiguration in {fp}"
    if finding.domain == Domain.ATTACK:
        return f"ATT&CK {code} ({sev}) observed in {fp}"
    return f"{code} ({sev}) in {fp}"


def _static_remediation(finding: Finding) -> str:
    if finding.control_gaps:
        ctrl_ids = [c.control_id for c in finding.control_gaps[:3]]
        return f"Implement or verify controls: {', '.join(ctrl_ids)}."
    if finding.attack_chain:
        techniques = [a.technique_id for a in finding.attack_chain[:2]]
        return (
            f"Address techniques {', '.join(techniques)} by reviewing "
            "applicable security controls for the affected asset."
        )
    return "Review and remediate according to the finding's severity and evidence location."
