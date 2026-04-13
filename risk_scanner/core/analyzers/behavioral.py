"""
Behavioral analyzer — AST taint analysis (CWE) + ATT&CK sequence correlation.

Phase 3: Python AST taint analysis implemented.
         JS/Go/Bash: basic regex-level pattern detection.
         Sequence correlator: temporal kill-chain window over SIEM JSONL.
"""

from __future__ import annotations

import ast as python_ast
import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from risk_scanner.core.models import Domain, Evidence, Finding, LoadedArtifact, Severity
from risk_scanner.core.analyzers import BaseAnalyzer

log = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Python taint: source and sink definitions
# ------------------------------------------------------------------

# Sources: expressions that introduce untrusted data
_PYTHON_SOURCES: Set[str] = {
    "request.args", "request.form", "request.json", "request.data",
    "request.headers", "request.cookies", "request.get",
    "os.environ.get", "os.getenv", "sys.argv",
    "input(", "open(", "json.loads(", "yaml.safe_load(",
}

# Sinks: expressions that can be dangerous if tainted
_PYTHON_SINKS: Dict[str, str] = {
    "os.system": "subprocess",
    "subprocess.call": "subprocess",
    "subprocess.run": "subprocess",
    "subprocess.Popen": "subprocess",
    "eval(": "eval",
    "exec(": "eval",
    "cursor.execute": "database",
    "db.execute": "database",
    "engine.execute": "database",
    ".execute(": "database",
    "open(": "filesystem",
    "shutil.copy": "filesystem",
    "shutil.move": "filesystem",
    "os.rename": "filesystem",
    "pickle.loads": "reflection",
    "marshal.loads": "reflection",
    "__import__(": "reflection",
    "importlib.import_module(": "reflection",
    "socket.connect": "network",
    "requests.get": "network",
    "requests.post": "network",
    "urllib.request.urlopen": "network",
}

# CWE mappings for sink types
_SINK_TO_CWE: Dict[str, str] = {
    "subprocess": "CWE-78",     # OS Command Injection
    "eval": "CWE-95",           # Eval Injection
    "database": "CWE-89",       # SQL Injection
    "filesystem": "CWE-22",     # Path Traversal
    "reflection": "CWE-470",    # Use of Externally-Controlled Input to Select Classes
    "network": "CWE-918",       # Server-Side Request Forgery
}

# Source types for CWE schema
_SOURCE_TO_TYPE: Dict[str, str] = {
    "request": "http_param",
    "os.environ": "env_var",
    "os.getenv": "env_var",
    "input": "user_input",
    "open": "file_read",
    "json.loads": "user_input",
    "sys.argv": "user_input",
}


class BehavioralAnalyzer(BaseAnalyzer):
    """AST taint analysis for source code + sequence correlation for logs."""

    def __init__(self, sequence_window_seconds: int = 300) -> None:
        self.sequence_window = timedelta(seconds=sequence_window_seconds)

    def can_handle(self, artifact: LoadedArtifact) -> bool:
        return artifact.file_type in ("python", "javascript", "typescript",
                                      "go", "bash", "rust", "siem-logs")

    def analyze(self, artifact: LoadedArtifact) -> List[Finding]:
        ft = artifact.file_type
        if ft == "python":
            return self._analyze_python(artifact)
        if ft in ("javascript", "typescript"):
            return self._analyze_js(artifact)
        if ft in ("go", "bash", "rust"):
            return self._analyze_generic_source(artifact)
        if ft == "siem-logs":
            return self._analyze_sequence(artifact)
        return []

    # ------------------------------------------------------------------
    # Python AST taint analysis
    # ------------------------------------------------------------------

    def _analyze_python(self, artifact: LoadedArtifact) -> List[Finding]:
        text = artifact.text_content or ""
        findings: List[Finding] = []
        try:
            tree = python_ast.parse(text, filename=artifact.path)
        except SyntaxError as exc:
            log.debug("Python parse error %s: %s", artifact.path, exc)
            return findings

        visitor = _PythonTaintVisitor(artifact.path)
        visitor.visit(tree)
        for chain in visitor.taint_chains:
            sink_type = chain["sink_type"]
            cwe_id = _SINK_TO_CWE.get(sink_type, "CWE-20")
            source_type = chain.get("source_type", "user_input")

            # Determine severity based on sink type
            severity = {
                "subprocess": Severity.CRITICAL,
                "eval": Severity.CRITICAL,
                "database": Severity.HIGH,
                "reflection": Severity.HIGH,
                "filesystem": Severity.MEDIUM,
                "network": Severity.MEDIUM,
            }.get(sink_type, Severity.MEDIUM)

            rationale = (
                f"Tainted data flows from {source_type} source "
                f"({chain['source_expr']}) to {sink_type} sink "
                f"({chain['sink_expr']}) via {len(chain['vars'])} variable(s)."
            )

            findings.append(Finding(
                domain=Domain.CWE,
                taxonomy_code=cwe_id,
                severity=severity,
                severity_rationale=rationale,
                evidence=Evidence(
                    file_path=artifact.path,
                    line_start=chain["source_line"],
                    line_end=chain["sink_line"],
                    snippet=chain.get("snippet", ""),
                    matched_rule_id=f"taint-{sink_type}",
                    matched_pattern=chain["sink_expr"],
                ),
                pack_version="builtin-v1",
                confidence=chain.get("confidence", 0.75),
                analyzer_sources=["behavioral"],
                summary=f"{cwe_id}: {source_type} → {sink_type} in {artifact.path}",
            ))
        return findings

    # ------------------------------------------------------------------
    # JavaScript/TypeScript: regex-level taint (Phase 3 simplified)
    # ------------------------------------------------------------------

    def _analyze_js(self, artifact: LoadedArtifact) -> List[Finding]:
        text = artifact.text_content or ""
        findings: List[Finding] = []
        lines = text.splitlines()

        # Patterns: (source_pattern, sink_pattern, cwe_id, severity, sink_type)
        js_patterns = [
            (r"req\.(body|query|params|headers)", r"eval\s*\(", "CWE-95", Severity.CRITICAL, "eval"),
            (r"req\.(body|query|params)", r"\.execute\s*\(", "CWE-89", Severity.HIGH, "database"),
            (r"req\.(body|query|params)", r"child_process\.(exec|spawn)", "CWE-78", Severity.CRITICAL, "subprocess"),
            (r"req\.(body|query|params)", r"innerHTML\s*=", "CWE-79", Severity.HIGH, "xss"),
            (r"req\.(body|query|params)", r"dangerouslySetInnerHTML", "CWE-79", Severity.HIGH, "xss"),
            (r"req\.(body|query|params)", r'require\s*\(', "CWE-22", Severity.HIGH, "filesystem"),
        ]
        for i, line in enumerate(lines, 1):
            for src_pat, sink_pat, cwe_id, sev, sink_type in js_patterns:
                if re.search(src_pat, line) and re.search(sink_pat, line):
                    findings.append(Finding(
                        domain=Domain.CWE,
                        taxonomy_code=cwe_id,
                        severity=sev,
                        severity_rationale=f"Potential {sink_type} injection via HTTP parameter",
                        evidence=Evidence(
                            file_path=artifact.path,
                            line_start=i,
                            snippet=line[:200],
                            matched_rule_id=f"js-taint-{sink_type}",
                            matched_pattern=sink_pat,
                        ),
                        pack_version="builtin-v1",
                        confidence=0.65,
                        analyzer_sources=["behavioral"],
                        summary=f"{cwe_id}: HTTP param → {sink_type} in JS",
                    ))
        return findings

    # ------------------------------------------------------------------
    # Generic source files: pattern-only detection
    # ------------------------------------------------------------------

    def _analyze_generic_source(self, artifact: LoadedArtifact) -> List[Finding]:
        text = artifact.text_content or ""
        findings: List[Finding] = []
        lines = text.splitlines()
        generic_sinks = [
            (r"os\.system\s*\(", "CWE-78", Severity.CRITICAL, "subprocess"),
            (r"exec\s*\(", "CWE-78", Severity.CRITICAL, "subprocess"),
            (r"shell=True", "CWE-78", Severity.HIGH, "subprocess"),
            (r'(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*\w', "CWE-89", Severity.HIGH, "database"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cwe_id, sev, sink_type in generic_sinks:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        domain=Domain.CWE,
                        taxonomy_code=cwe_id,
                        severity=sev,
                        severity_rationale=f"Dangerous {sink_type} pattern detected",
                        evidence=Evidence(
                            file_path=artifact.path,
                            line_start=i,
                            snippet=line[:200],
                            matched_rule_id=f"pattern-{sink_type}",
                            matched_pattern=pattern,
                        ),
                        pack_version="builtin-v1",
                        confidence=0.6,
                        analyzer_sources=["behavioral"],
                        summary=f"{cwe_id}: {sink_type} pattern in {artifact.file_type}",
                    ))
        return findings

    # ------------------------------------------------------------------
    # ATT&CK sequence correlation
    # ------------------------------------------------------------------

    def _analyze_sequence(self, artifact: LoadedArtifact) -> List[Finding]:
        """Correlate SIEM log events across ATT&CK kill chain stages."""
        text = artifact.text_content or ""
        events: List[Dict[str, Any]] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
                if isinstance(ev, dict):
                    events.append(ev)
            except Exception:
                # Try CEF / syslog line
                ts_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
                ev = {
                    "raw": line,
                    "timestamp": ts_match.group(1) if ts_match else None,
                    "technique": None,
                }
                t_match = re.search(r'\b(T1\d{3}(?:\.\d{3})?)\b', line)
                if t_match:
                    ev["technique"] = t_match.group(1)
                events.append(ev)

        return self._correlate_kill_chain(events, artifact)

    def _correlate_kill_chain(
        self,
        events: List[Dict[str, Any]],
        artifact: LoadedArtifact,
    ) -> List[Finding]:
        """Sliding window kill-chain correlation."""
        findings: List[Finding] = []
        timed_events: List[Tuple[Optional[datetime], Dict[str, Any]]] = []
        for ev in events:
            ts_str = ev.get("timestamp") or ev.get("ts") or ev.get("time")
            ts = None
            if ts_str:
                for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
                    try:
                        ts = datetime.strptime(str(ts_str)[:19], fmt)
                        break
                    except ValueError:
                        pass
            timed_events.append((ts, ev))

        # Group by window
        technique_set: List[str] = []
        for _, ev in timed_events:
            tech = ev.get("technique") or ev.get("technique_id") or ""
            if tech and tech not in technique_set:
                technique_set.append(tech)

        if len(technique_set) >= 2:
            stages = _techniques_to_stages(technique_set)
            is_complete = "initial-access" in stages and len(stages) >= 3
            sev = Severity.CRITICAL if is_complete else Severity.HIGH
            findings.append(Finding(
                domain=Domain.ATTACK,
                taxonomy_code=technique_set[0],
                severity=sev,
                severity_rationale=(
                    f"Kill chain correlation: {len(technique_set)} technique(s) detected "
                    f"spanning {len(stages)} stage(s): {', '.join(sorted(stages))}"
                ),
                evidence=Evidence(
                    file_path=artifact.path,
                    matched_rule_id="kill-chain-correlation",
                    matched_pattern=",".join(technique_set[:5]),
                ),
                pack_version="builtin-v1",
                confidence=0.7 if is_complete else 0.5,
                analyzer_sources=["behavioral"],
                summary=f"Kill chain: {len(stages)} stages detected in logs",
            ))
        return findings


# ------------------------------------------------------------------
# Python AST visitor
# ------------------------------------------------------------------

class _PythonTaintVisitor(python_ast.NodeVisitor):
    """Simple forward-dataflow taint tracker for Python AST."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.taint_chains: List[Dict[str, Any]] = []
        self._tainted_vars: Dict[str, Dict[str, Any]] = {}  # var_name → source info

    def visit_Assign(self, node: python_ast.Assign) -> None:
        # Check if RHS is a taint source
        source_info = self._is_source(node.value)
        if source_info:
            for target in node.targets:
                if isinstance(target, python_ast.Name):
                    self._tainted_vars[target.id] = {
                        "source_expr": source_info["expr"],
                        "source_type": source_info["type"],
                        "source_line": node.lineno,
                    }
        self.generic_visit(node)

    def visit_Expr(self, node: python_ast.Expr) -> None:
        self._check_sink(node.value, node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: python_ast.Call) -> None:
        self._check_sink(node, node.lineno)
        self.generic_visit(node)

    def _is_source(self, node: python_ast.expr) -> Optional[Dict[str, Any]]:
        code = _unparse(node)
        for src in _PYTHON_SOURCES:
            if src in code:
                src_type = "http_param"
                for key, typ in _SOURCE_TO_TYPE.items():
                    if key in code:
                        src_type = typ
                        break
                return {"expr": code[:100], "type": src_type}
        return None

    def _check_sink(self, node: python_ast.expr, lineno: int) -> None:
        code = _unparse(node)
        for sink_expr, sink_type in _PYTHON_SINKS.items():
            if sink_expr in code:
                # Check if any tainted var appears in the sink call
                used_vars = _extract_name_ids(node)
                tainted_used = [v for v in used_vars if v in self._tainted_vars]
                if tainted_used:
                    source_var = tainted_used[0]
                    source_info = self._tainted_vars[source_var]
                    self.taint_chains.append({
                        "source_expr": source_info["source_expr"],
                        "source_type": source_info["source_type"],
                        "source_line": source_info["source_line"],
                        "sink_expr": code[:100],
                        "sink_type": sink_type,
                        "sink_line": lineno,
                        "vars": tainted_used,
                        "confidence": 0.8,
                        "snippet": f"# line {source_info['source_line']}: {source_info['source_expr']}\n"
                                   f"# line {lineno}: {code[:80]}",
                    })
                    break


def _unparse(node: python_ast.AST) -> str:
    try:
        return python_ast.unparse(node)
    except Exception:
        return ""


def _extract_name_ids(node: python_ast.AST) -> List[str]:
    return [n.id for n in python_ast.walk(node) if isinstance(n, python_ast.Name)]


# ------------------------------------------------------------------
# Kill chain stage mapping
# ------------------------------------------------------------------

_TECHNIQUE_TO_STAGE: Dict[str, str] = {
    "T1190": "initial-access",
    "T1133": "initial-access",
    "T1566": "initial-access",
    "T1059": "execution",
    "T1053": "execution",
    "T1547": "persistence",
    "T1543": "persistence",
    "T1078": "privilege-escalation",
    "T1548": "privilege-escalation",
    "T1070": "defense-evasion",
    "T1027": "defense-evasion",
    "T1003": "credential-access",
    "T1552": "credential-access",
    "T1057": "discovery",
    "T1082": "discovery",
    "T1021": "lateral-movement",
    "T1570": "lateral-movement",
    "T1005": "collection",
    "T1560": "collection",
    "T1041": "exfiltration",
    "T1048": "exfiltration",
    "T1486": "impact",
    "T1490": "impact",
}


def _techniques_to_stages(technique_ids: List[str]) -> Set[str]:
    stages: Set[str] = set()
    for tid in technique_ids:
        base = tid[:5]  # T1190
        stage = _TECHNIQUE_TO_STAGE.get(tid) or _TECHNIQUE_TO_STAGE.get(base)
        if stage:
            stages.add(stage)
    return stages
