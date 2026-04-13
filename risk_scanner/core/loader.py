"""
Artifact loader — magic detection, archive unpacking, normalization.

Accepts any file path or directory and returns one or more LoadedArtifact
objects ready for domain classification and analysis.
"""

from __future__ import annotations

import ast as python_ast
import json
import logging
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from risk_scanner.core.models import LoadedArtifact

log = logging.getLogger(__name__)

# Keywords used to classify artifacts without magic bytes
_CVE_KEYWORDS = {"bomFormat", "SPDXID", "packages", "vulnerabilities", "components",
                 "cyclonedx", "spdx", "bom-ref", "purl"}
_POLICY_KEYWORDS = {"resource", "provider", "terraform", "kubernetes", "apiVersion",
                    "kind", "spec", "template", "aws_", "google_", "azurerm_",
                    "CloudFormation", "AWSTemplateFormatVersion"}
_ATTACK_KEYWORDS = {"technique", "tactic", "kill_chain", "mitre", "T1", "TA00",
                    "ioc", "indicator", "hash", "sha256", "ip_address", "domain"}
_FRAMEWORK_KEYWORDS = {"control", "requirement", "evidence", "audit", "compliance",
                       "soc2", "nist", "iso27001", "cis", "pci", "hipaa"}
_CWE_KEYWORDS = {"def ", "import ", "function ", "class ", "var ", "const ",
                 "subprocess", "eval(", "exec(", "os.system", "cursor.execute",
                 "innerHTML", "dangerouslySetInnerHTML"}

# Recognized source file extensions → file_type
_SOURCE_EXT: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".go": "go",
    ".sh": "bash",
    ".bash": "bash",
    ".rs": "rust",
}

# IaC extensions → file_type
_IAC_EXT: Dict[str, str] = {
    ".tf": "terraform",
    ".hcl": "terraform",
}


class ArtifactLoader:
    """Load an artifact (file or directory) into LoadedArtifact(s)."""

    def load(self, path: str) -> List[LoadedArtifact]:
        p = Path(path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Artifact not found: {path}")
        if p.is_dir():
            return self._load_directory(p)
        return [self._load_file(p)]

    # ------------------------------------------------------------------
    # Directory walker
    # ------------------------------------------------------------------

    def _load_directory(self, directory: Path) -> List[LoadedArtifact]:
        artifacts: List[LoadedArtifact] = []
        for fp in sorted(directory.rglob("*")):
            if fp.is_file() and not _is_hidden(fp):
                try:
                    artifacts.append(self._load_file(fp))
                except Exception as exc:
                    log.debug("Skipping %s: %s", fp, exc)
        return artifacts

    # ------------------------------------------------------------------
    # Single file loader
    # ------------------------------------------------------------------

    def _load_file(self, path: Path) -> LoadedArtifact:
        raw = path.read_bytes()
        size = len(raw)
        text: Optional[str] = None
        parsed: Optional[Dict[str, Any]] = None
        archive_members: List[str] = []

        # Try text decoding
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            pass

        # Try JSON parse
        if text:
            try:
                parsed = json.loads(text)
            except Exception:
                pass

        # Try YAML parse (if not JSON)
        if text and parsed is None:
            try:
                import yaml
                result = yaml.safe_load(text)
                if isinstance(result, dict):
                    parsed = result
            except Exception:
                pass

        # Archive unpacking
        if zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path) as zf:
                    archive_members = zf.namelist()
            except Exception:
                pass
        elif tarfile.is_tarfile(path):
            try:
                with tarfile.open(path) as tf:
                    archive_members = tf.getnames()
            except Exception:
                pass

        file_type = self._detect_file_type(path, text, parsed)
        mime_type = _guess_mime(path, parsed)
        keywords = _extract_keywords(text or "", parsed)
        manifest_keys = _extract_manifest_keys(parsed)

        return LoadedArtifact(
            path=str(path),
            raw_content=raw,
            text_content=text,
            file_type=file_type,
            mime_type=mime_type,
            detected_keywords=keywords,
            manifest_keys=manifest_keys,
            size_bytes=size,
            archive_members=archive_members,
            parsed_data=parsed,
        )

    # ------------------------------------------------------------------
    # File type detection
    # ------------------------------------------------------------------

    def _detect_file_type(
        self,
        path: Path,
        text: Optional[str],
        parsed: Optional[Any],
    ) -> str:
        ext = path.suffix.lower()

        # Source files
        if ext in _SOURCE_EXT:
            return _SOURCE_EXT[ext]

        # IaC
        if ext in _IAC_EXT:
            return _IAC_EXT[ext]

        # SBOM detection (JSON/XML)
        if ext in (".json", ".xml", ""):
            if isinstance(parsed, dict):
                if "bomFormat" in parsed or "components" in parsed:
                    return "sbom-cyclonedx"
                if "SPDXID" in parsed or "packages" in parsed:
                    return "sbom-spdx"
                if "AWSTemplateFormatVersion" in parsed or "Resources" in parsed:
                    return "cloudformation"

        # YAML files — k8s, terraform, generic
        if ext in (".yaml", ".yml"):
            if isinstance(parsed, dict):
                if "apiVersion" in parsed and "kind" in parsed:
                    return "kubernetes"
                if "resource" in parsed or "provider" in parsed:
                    return "terraform"
            return "yaml"

        # SPDX tag-value
        if ext in (".spdx", ".tv"):
            return "sbom-spdx"

        # Log / SIEM
        if ext in (".log", ".jsonl", ".ndjson"):
            return "siem-logs"

        # Evidence docs
        if ext == ".pdf":
            return "evidence-pdf"
        if ext in (".csv",):
            return "evidence-csv"
        if ext in (".xlsx", ".xls"):
            return "evidence-xlsx"

        # Fallback: detect by content keywords
        if text:
            if any(kw in text for kw in ("bomFormat", "SPDXID", "cyclonedx")):
                return "sbom-cyclonedx"
            if any(kw in text for kw in ("resource \"aws", "resource \"google", "provider \"aws")):
                return "terraform"
            if any(kw in text for kw in ("apiVersion:", "kind: Deployment", "kind: Service")):
                return "kubernetes"

        return "unknown"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _is_hidden(path: Path) -> bool:
    return any(part.startswith(".") for part in path.parts[-3:])


def _guess_mime(path: Path, parsed: Optional[Any]) -> str:
    ext = path.suffix.lower()
    if ext == ".json" or isinstance(parsed, dict):
        return "application/json"
    if ext in (".yaml", ".yml"):
        return "application/yaml"
    if ext == ".xml":
        return "application/xml"
    if ext in (".tf", ".hcl"):
        return "text/plain"
    if ext in (".py", ".js", ".ts", ".go", ".sh", ".rs"):
        return "text/plain"
    return "application/octet-stream"


def _extract_keywords(text: str, parsed: Optional[Any]) -> List[str]:
    found = []
    for kw in (_CVE_KEYWORDS | _POLICY_KEYWORDS | _ATTACK_KEYWORDS |
               _FRAMEWORK_KEYWORDS | _CWE_KEYWORDS):
        if kw in text:
            found.append(kw)
    return found[:50]  # cap at 50


def _extract_manifest_keys(parsed: Optional[Any]) -> List[str]:
    if not isinstance(parsed, dict):
        return []
    return list(parsed.keys())[:30]
