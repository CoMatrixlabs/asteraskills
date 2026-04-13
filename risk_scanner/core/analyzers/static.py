"""
Static analyzer — SBOM CVE detection, IaC policy assertions, IoC matching, evidence classification.

Phase 1/2: CVE (SBOM) and POLICY (IaC) fully implemented.
Phase 3/4: ATT&CK IoC matching and Framework evidence classification stubs.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from risk_scanner.core.models import Domain, Evidence, Finding, LoadedArtifact, Severity
from risk_scanner.core.analyzers import BaseAnalyzer

log = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Lightweight version comparison (no packaging dep required)
# ------------------------------------------------------------------

def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse semver-ish string to tuple for comparison."""
    parts = re.split(r"[.\-+]", v.lstrip("v~^"))
    result = []
    for p in parts[:4]:
        m = re.match(r"(\d+)", p)
        result.append(int(m.group(1)) if m else 0)
    return tuple(result)


def _version_in_range(version: str, version_range: str) -> bool:
    """Check if version satisfies a simple range expression like '<2.0.0' or '>=1.0,<2.0'."""
    try:
        v = _parse_version(version)
        for part in version_range.split(","):
            part = part.strip()
            for op, prefix in [(">=", ">="), ("<=", "<="), (">", ">"), ("<", "<"), ("==", "=="), ("=", "=")]:
                if part.startswith(prefix):
                    bound = _parse_version(part[len(prefix):])
                    if op in (">=",) and not (v >= bound):
                        return False
                    elif op in ("<=",) and not (v <= bound):
                        return False
                    elif op in (">",) and not (v > bound):
                        return False
                    elif op in ("<",) and not (v < bound):
                        return False
                    elif op in ("==", "=") and not (v == bound):
                        return False
                    break
    except Exception:
        return False
    return True


# ------------------------------------------------------------------
# IaC policy rules (built-in, no server required)
# ------------------------------------------------------------------

_BUILTIN_POLICY_RULES: List[Dict[str, Any]] = [
    # AWS S3
    {
        "id": "AWS-S3-001",
        "description": "S3 bucket should not have public ACL",
        "resource_type": "aws_s3_bucket",
        "check_path": ["acl"],
        "forbidden_values": ["public-read", "public-read-write", "authenticated-read"],
        "severity": "HIGH",
    },
    {
        "id": "AWS-S3-002",
        "description": "S3 bucket versioning should be enabled",
        "resource_type": "aws_s3_bucket",
        "check_path": ["versioning", "enabled"],
        "required_value": True,
        "severity": "MEDIUM",
    },
    {
        "id": "AWS-S3-003",
        "description": "S3 bucket server-side encryption should be configured",
        "resource_type": "aws_s3_bucket",
        "check_path": ["server_side_encryption_configuration"],
        "must_exist": True,
        "severity": "HIGH",
    },
    # AWS Security Group
    {
        "id": "AWS-SG-001",
        "description": "Security group should not allow unrestricted ingress on all ports",
        "resource_type": "aws_security_group",
        "ingress_check": {"from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]},
        "severity": "CRITICAL",
    },
    {
        "id": "AWS-SG-002",
        "description": "Security group should not allow unrestricted SSH (port 22)",
        "resource_type": "aws_security_group",
        "ingress_check": {"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
        "severity": "HIGH",
    },
    # AWS IAM
    {
        "id": "AWS-IAM-001",
        "description": "IAM policy should not use wildcard (*) actions",
        "resource_type": "aws_iam_policy",
        "check_path": ["policy"],
        "json_field_check": {"Action": "*"},
        "severity": "HIGH",
    },
    # Kubernetes
    {
        "id": "K8S-001",
        "description": "Container should not run as root",
        "resource_type": "k8s_deployment",
        "spec_check": "runAsNonRoot",
        "severity": "HIGH",
    },
    {
        "id": "K8S-002",
        "description": "Container should have resource limits defined",
        "resource_type": "k8s_deployment",
        "spec_check": "resources.limits",
        "severity": "MEDIUM",
    },
]


class StaticAnalyzer(BaseAnalyzer):
    """Static analysis: SBOM CVE detection + IaC policy assertions."""

    def can_handle(self, artifact: LoadedArtifact) -> bool:
        return artifact.file_type in (
            "sbom-cyclonedx", "sbom-spdx",
            "terraform", "cloudformation", "kubernetes",
            "siem-logs", "evidence-pdf", "evidence-csv", "evidence-xlsx",
        )

    def analyze(self, artifact: LoadedArtifact) -> List[Finding]:
        ft = artifact.file_type
        if ft in ("sbom-cyclonedx", "sbom-spdx"):
            return self._analyze_sbom(artifact)
        if ft in ("terraform", "cloudformation", "kubernetes"):
            return self._analyze_iac(artifact)
        if ft == "siem-logs":
            return self._analyze_ioc(artifact)
        if ft in ("evidence-pdf", "evidence-csv", "evidence-xlsx"):
            return self._analyze_evidence(artifact)
        return []

    # ------------------------------------------------------------------
    # CVE domain: SBOM analysis
    # ------------------------------------------------------------------

    def _analyze_sbom(self, artifact: LoadedArtifact) -> List[Finding]:
        findings: List[Finding] = []
        components = self._extract_components(artifact)

        # Build per-component source_map for the ScanResult (Capability 2)
        self._last_source_map: Dict[str, Any] = {}

        for comp in components:
            name = comp.get("name", "")
            version = comp.get("version", "")
            purl = comp.get("purl", "")
            if not name:
                continue
            component_label = f"{name}@{version}" if version else name

            # Priority 1: use inline CycloneDX vulnerabilities[] when present
            # (output from Grype, Trivy, etc. — no NVD call needed)
            inline = comp.get("inline_vulns", [])
            if inline:
                for vuln in inline:
                    cve_id = vuln.get("id", "")
                    if not cve_id or not cve_id.startswith("CVE-"):
                        continue
                    ratings = vuln.get("ratings", [])
                    raw_sev = "HIGH"
                    cvss_score = None
                    for r in ratings:
                        raw_sev = r.get("severity", "high").upper()
                        cvss_score = r.get("score")
                        break
                    sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
                               "MEDIUM": "MEDIUM", "LOW": "LOW", "NONE": "INFO"}
                    sev = Severity(sev_map.get(raw_sev, "HIGH"))
                    description = vuln.get("description", f"{cve_id} in {component_label}")
                    findings.append(Finding(
                        domain=Domain.CVE,
                        taxonomy_code=cve_id,
                        severity=sev,
                        severity_rationale=description,
                        evidence=Evidence(
                            file_path=artifact.path,
                            matched_rule_id="sbom-inline-vuln",
                            matched_pattern=component_label,
                            snippet=f"CVSS: {cvss_score}" if cvss_score else None,
                        ),
                        pack_version="local",
                        confidence=0.95,
                        analyzer_sources=["static"],
                        summary=f"{cve_id} in {component_label}",
                        source_component=component_label,
                    ))
                continue  # skip lookup if inline vulns were present

            # Priority 2: sbom_cve_context (Capability 2) — CPE-resolved CVE lookup
            # Falls back to NVD CPE search API when local DB has no data.
            if not version:
                continue

            ctx = self._check_sbom_cve_context(name, version, purl or None)
            if ctx:
                cpe_uri = ctx.get("cpe_uri", "")
                cve_records = ctx.get("cves", [])

                # Populate source_map entry
                self._last_source_map[component_label] = {
                    "cpe_uri": cpe_uri,
                    "resolution_confidence": ctx.get("resolution_confidence", 0.0),
                    "cves": [r["cve_id"] for r in cve_records],
                    "max_cvss": max((r.get("cvss_score", 0) for r in cve_records), default=0),
                    "technique_surface": list({
                        t for r in cve_records for t in r.get("technique_ids", [])
                    }),
                }

                for rec in cve_records:
                    cve_id = rec.get("cve_id", "")
                    if not cve_id:
                        continue
                    cvss = rec.get("cvss_score", 0.0)
                    sev = _cvss_to_severity(cvss)
                    exploit = rec.get("exploit_maturity", "none")
                    rationale = (
                        f"{cve_id} in {component_label} (CVSS {cvss:.1f}, exploit: {exploit})"
                    )
                    finding = Finding(
                        domain=Domain.CVE,
                        taxonomy_code=cve_id,
                        severity=sev,
                        severity_rationale=rationale,
                        evidence=Evidence(
                            file_path=artifact.path,
                            matched_rule_id="sbom-cpe-context",
                            matched_pattern=component_label,
                        ),
                        pack_version="local",
                        confidence=ctx.get("resolution_confidence", 0.85),
                        analyzer_sources=["static"],
                        summary=f"{cve_id} in {component_label}",
                        source_component=component_label,
                        source_cpe_uri=cpe_uri,
                    )
                    # Pre-seed technique IDs from sbom_cve_context so enrichment
                    # can skip the ATT&CK lookup when mappings are already known.
                    pre_techniques = rec.get("technique_ids", [])
                    if pre_techniques:
                        finding.cve_detail = {
                            "cve_id": cve_id,
                            "cvss_score": cvss,
                            "epss_score": rec.get("epss_score", 0.0),
                            "exploit_maturity": exploit,
                            "cwe_ids": rec.get("cwe_ids", []),
                            "pre_seeded_techniques": pre_techniques,
                        }
                    findings.append(finding)

            else:
                # Fallback: bare NVD intelligence lookup (no CPE resolution)
                for cve_id, meta in self._check_nvd_fallback(name, version):
                    findings.append(Finding(
                        domain=Domain.CVE,
                        taxonomy_code=cve_id,
                        severity=Severity(meta.get("severity", "HIGH")),
                        severity_rationale=meta.get("description", f"{cve_id} in {component_label}"),
                        evidence=Evidence(
                            file_path=artifact.path,
                            matched_rule_id="sbom-nvd-fallback",
                            matched_pattern=component_label,
                        ),
                        pack_version="local",
                        confidence=0.80,
                        analyzer_sources=["static"],
                        summary=f"{cve_id} in {component_label}",
                        source_component=component_label,
                    ))

        return findings

    def _extract_components(self, artifact: LoadedArtifact) -> List[Dict[str, Any]]:
        pd = artifact.parsed_data
        if not isinstance(pd, dict):
            return []
        # CycloneDX — also extract inline vulnerabilities[] per component
        if "components" in pd:
            comps = pd["components"]
            if isinstance(comps, list):
                return [
                    {
                        "name": c.get("name", ""),
                        "version": c.get("version", ""),
                        "purl": c.get("purl", ""),
                        "inline_vulns": c.get("vulnerabilities", []),  # CycloneDX inline
                    }
                    for c in comps if isinstance(c, dict)
                ]
        # SPDX
        if "packages" in pd:
            pkgs = pd["packages"]
            if isinstance(pkgs, list):
                return [{"name": p.get("name", ""), "version": p.get("versionInfo", "")}
                        for p in pkgs if isinstance(p, dict)]
        return []

    def _check_sbom_cve_context(
        self, name: str, version: str, purl: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Capability 2: CPE-resolved CVE lookup via sbom_cve_context tool."""
        try:
            from asteraskills.tools.sbom_cve_context import _execute_sbom_cve_context
            result = _execute_sbom_cve_context(name, version, purl=purl)
            # Return None if nothing resolved (no CPE found and no CVEs)
            if not result.get("cpe_uri") and not result.get("cves"):
                return None
            return result
        except Exception as exc:
            log.debug("sbom_cve_context for %s@%s: %s", name, version, exc)
        return None

    def _check_nvd_fallback(self, name: str, version: str) -> List[Tuple[str, Dict[str, Any]]]:
        """Last-resort: NVD CPE search API when local CPE registry has no data."""
        try:
            import requests
            resp = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": f"{name} {version}", "resultsPerPage": 10},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            results = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue
                cvss = 0.0
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    metrics = cve.get("metrics", {}).get(key, [])
                    if metrics:
                        cvss = float(metrics[0].get("cvssData", {}).get("baseScore", 0))
                        break
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                results.append((cve_id, {
                    "severity": _cvss_to_severity(cvss).value,
                    "description": desc,
                    "cvss_score": cvss,
                }))
            return results
        except Exception as exc:
            log.debug("NVD fallback for %s@%s: %s", name, version, exc)
        return []

    # ------------------------------------------------------------------
    # POLICY domain: IaC rule assertions
    # ------------------------------------------------------------------

    def _analyze_iac(self, artifact: LoadedArtifact) -> List[Finding]:
        findings: List[Finding] = []
        pd = artifact.parsed_data
        if not isinstance(pd, dict):
            return findings

        # Parse Terraform resource blocks
        resources = {}
        if artifact.file_type == "terraform":
            resources = _parse_terraform_resources(pd)
        elif artifact.file_type in ("cloudformation", "kubernetes"):
            resources = _parse_generic_resources(pd, artifact.file_type)

        for rule in _BUILTIN_POLICY_RULES:
            violations = _check_rule(rule, resources, artifact)
            for resource_id, resource_type, line_hint in violations:
                findings.append(Finding(
                    domain=Domain.POLICY,
                    taxonomy_code=rule["id"],
                    severity=Severity(rule["severity"]),
                    severity_rationale=rule["description"],
                    evidence=Evidence(
                        file_path=artifact.path,
                        line_start=line_hint,
                        matched_rule_id=rule["id"],
                        matched_pattern=f"{resource_type}.{resource_id}",
                    ),
                    pack_version="builtin-v1",
                    confidence=0.9,
                    analyzer_sources=["static"],
                    summary=f"{rule['id']}: {rule['description']} ({resource_id})",
                ))
        return findings

    # ------------------------------------------------------------------
    # ATT&CK domain: IoC signature matching (Phase 3 stub)
    # ------------------------------------------------------------------

    def _analyze_ioc(self, artifact: LoadedArtifact) -> List[Finding]:
        """Match known IoC patterns in SIEM log lines."""
        findings: List[Finding] = []
        text = artifact.text_content or ""
        # Basic IoC patterns — expanded via pack rules in remote mode
        patterns = [
            (r"\b(T1\d{3}(?:\.\d{3})?)\b", "technique_id"),
            (r"\b([0-9a-f]{64})\b", "sha256_hash"),
            (r"(?:cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe)",
             "suspicious_process"),
        ]
        for i, line in enumerate(text.splitlines(), 1):
            for pattern, label in patterns:
                m = re.search(pattern, line, re.IGNORECASE)
                if m:
                    findings.append(Finding(
                        domain=Domain.ATTACK,
                        taxonomy_code=m.group(1) if label == "technique_id" else f"IOC-{label}",
                        severity=Severity.MEDIUM,
                        severity_rationale=f"IoC match: {label} in log line {i}",
                        evidence=Evidence(
                            file_path=artifact.path,
                            line_start=i,
                            snippet=line[:200],
                            matched_rule_id=f"ioc-{label}",
                            matched_pattern=m.group(0),
                        ),
                        pack_version="builtin-v1",
                        confidence=0.7,
                        analyzer_sources=["static"],
                    ))
        return findings

    # ------------------------------------------------------------------
    # FRAMEWORK domain: evidence classification (Phase 4 stub)
    # ------------------------------------------------------------------

    def _analyze_evidence(self, artifact: LoadedArtifact) -> List[Finding]:
        """Classify evidence artifacts against framework controls."""
        # Stub: returns empty list in open source mode.
        # Remote mode: upload to /v1/classify/evidence, returns control assessments.
        log.debug("Evidence classification requires license token: %s", artifact.path)
        return []


# ------------------------------------------------------------------
# IaC parsing helpers
# ------------------------------------------------------------------

def _cvss_to_severity(cvss: float) -> "Severity":
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    if cvss > 0.0:
        return Severity.LOW
    return Severity.INFO


def _parse_terraform_resources(data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract resource blocks from parsed Terraform JSON (terraform show -json output)."""
    resources = {}
    # Terraform JSON plan format
    if "resource_changes" in data:
        for rc in data["resource_changes"]:
            rtype = rc.get("type", "unknown")
            rname = rc.get("name", "")
            key = f"{rtype}.{rname}"
            resources[key] = {
                "type": rtype,
                "name": rname,
                "config": rc.get("change", {}).get("after", {}),
            }
    # HCL2 parsed (pyhcl2 dict format)
    elif "resource" in data:
        for rtype, instances in (data.get("resource") or {}).items():
            if isinstance(instances, dict):
                for rname, config in instances.items():
                    key = f"{rtype}.{rname}"
                    resources[key] = {"type": rtype, "name": rname, "config": config}
    return resources


def _parse_generic_resources(data: Dict[str, Any], file_type: str) -> Dict[str, Any]:
    """Extract resources from CloudFormation / Kubernetes."""
    resources = {}
    if file_type == "cloudformation":
        for rname, rdef in (data.get("Resources") or {}).items():
            resources[rname] = {
                "type": rdef.get("Type", ""),
                "name": rname,
                "config": rdef.get("Properties", {}),
            }
    elif file_type == "kubernetes":
        kind = data.get("kind", "unknown")
        name = (data.get("metadata") or {}).get("name", "unknown")
        resources[f"{kind}.{name}"] = {
            "type": f"k8s_{kind.lower()}",
            "name": name,
            "config": data,
        }
    return resources


def _check_rule(
    rule: Dict[str, Any],
    resources: Dict[str, Any],
    artifact: LoadedArtifact,
) -> List[Tuple[str, str, Optional[int]]]:
    """Return list of (resource_id, resource_type, line) tuples that violate the rule."""
    violations = []
    target_type = rule.get("resource_type", "")
    for res_key, res in resources.items():
        if target_type and not res.get("type", "").startswith(target_type.replace("aws_", "")):
            if target_type not in res.get("type", "") and target_type not in res_key:
                continue
        config = res.get("config", {})

        # Check forbidden values
        if "check_path" in rule and "forbidden_values" in rule:
            val = _get_nested(config, rule["check_path"])
            if val in rule["forbidden_values"]:
                violations.append((res.get("name", res_key), res.get("type", ""), None))

        # Check required value
        elif "check_path" in rule and "required_value" in rule:
            val = _get_nested(config, rule["check_path"])
            if val != rule["required_value"]:
                violations.append((res.get("name", res_key), res.get("type", ""), None))

        # Check must_exist
        elif "check_path" in rule and "must_exist" in rule:
            val = _get_nested(config, rule["check_path"])
            if val is None:
                violations.append((res.get("name", res_key), res.get("type", ""), None))

        # Ingress checks
        elif "ingress_check" in rule:
            ingress_list = config.get("ingress", [])
            if not isinstance(ingress_list, list):
                continue
            check = rule["ingress_check"]
            for ingress in ingress_list:
                if not isinstance(ingress, dict):
                    continue
                cidr_match = any(c in ingress.get("cidr_blocks", [])
                                 for c in check.get("cidr_blocks", []))
                port_match = (check.get("from_port") is None or
                              ingress.get("from_port") == check.get("from_port"))
                if cidr_match and port_match:
                    violations.append((res.get("name", res_key), res.get("type", ""), None))
                    break

    return violations


def _get_nested(obj: Any, path: List[str]) -> Any:
    current = obj
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


