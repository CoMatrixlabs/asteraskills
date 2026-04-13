"""
detection_scenarios_ingest.py — Ingest detection scenario guides into Qdrant.

Parses cve_detection_scenarios.md and other_detection_usecases.md into
Q&A chunks and structured playbook cards, then upserts to Qdrant:

  Collection: detection_scenarios  — one document per Q&A pair
  Collection: detection_playbooks  — structured procedure cards

Usage:
    python -m asteraskills.ingestion.detection_scenarios_ingest
    python -m asteraskills.ingestion.detection_scenarios_ingest \\
        --files path/to/a.md path/to/b.md --dry-run

CLI also usable from: asteraskills ingest detection-scenarios
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)

# ── Default source file locations ──────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parents[5]  # asteraskills → Lexy → repo root
_CAUSALGRAPHS = _REPO_ROOT.parent / "Nexcraft" / "causalgraphs"

DEFAULT_SCENARIO_FILES = [
    _CAUSALGRAPHS / "cve_detection_scenarios.md",
    _CAUSALGRAPHS / "other_detection_usecases.md",
]

DEFAULT_PLAYBOOK_FILES = [
    _CAUSALGRAPHS / "detection_playbooks_by_source.md",
]

# ── ATT&CK / tool regexes for metadata extraction ──────────────────────────────
_ATTACK_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
_KQL_BLOCK_RE = re.compile(r"```kql\n(.*?)```", re.DOTALL)
_SPLUNK_BLOCK_RE = re.compile(r"```splunk\n(.*?)```", re.DOTALL)

# Tools/platforms mentioned in scenarios
_TOOL_KEYWORDS = {
    "kql": ["kql", "kusto", "log analytics", "advanced hunting"],
    "splunk": ["splunk", "spl", "index="],
    "elastic": ["elastic", "kibana", "ecs"],
    "sentinel": ["sentinel", "microsoft sentinel"],
    "defender": ["defender", "mde", "dfe", "devicetvmsoftware"],
    "tenable": ["tenable", "nessus"],
    "nmap": ["nmap"],
    "auditd": ["auditd", "ausearch"],
    "ansible": ["ansible"],
    "kubectl": ["kubectl", "k8s", "kubernetes"],
}


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class ScenarioChunk:
    """One Q&A pair from a scenario guide, ready for vector embedding."""
    chunk_id: str                    # deterministic hash of scenario+question
    text: str                        # full Q+A text (embedded)
    scenario_id: str                 # e.g. "cve-01", "sentinel-03"
    scenario_title: str              # H2 scenario title
    question: str                    # the Q line
    answer_summary: str              # first 300 chars of answer
    source_file: str                 # basename of source markdown
    domain: str                      # secops | appsec | vm | detection_eng
    role_level: str                  # junior | mid | senior
    cve_examples: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    tools_mentioned: List[str] = field(default_factory=list)
    has_kql: bool = False
    has_queries: bool = False
    difficulty: int = 1              # 1=beginner, 2=intermediate, 3=advanced

    def to_qdrant_payload(self) -> dict:
        return {
            "chunk_id": self.chunk_id,
            "scenario_id": self.scenario_id,
            "scenario_title": self.scenario_title,
            "question": self.question,
            "answer_summary": self.answer_summary,
            "source_file": self.source_file,
            "domain": self.domain,
            "role_level": self.role_level,
            "cve_examples": self.cve_examples,
            "attack_techniques": self.attack_techniques,
            "tools_mentioned": self.tools_mentioned,
            "has_kql": self.has_kql,
            "has_queries": self.has_queries,
            "difficulty": self.difficulty,
        }


@dataclass
class PlaybookCard:
    """A structured investigation playbook card with natural language investigation questions."""
    card_id: str
    text: str                              # full card text (embedded)
    title: str
    trigger: str                           # when to use this card
    domain: str
    output_type: str                       # decision | checklist | nl_questions | reference
    # Data source fields (populated for source-based playbooks)
    source_id: str = ""                    # e.g. "windows_security_events"
    investigation_type: str = ""           # e.g. "lateral_movement", "privilege_escalation"
    platform_hints: List[str] = field(default_factory=list)   # ["Sentinel", "Splunk", ...]
    primary_tables: List[str] = field(default_factory=list)   # ["SecurityEvent", ...]
    investigation_questions: List[str] = field(default_factory=list)  # NL questions
    attack_techniques: List[str] = field(default_factory=list)
    # Legacy fields kept for backward compat with Q&A playbook cards
    steps_count: int = 0
    tags: List[str] = field(default_factory=list)
    source_file: str = ""

    def to_qdrant_payload(self) -> dict:
        return {
            "card_id": self.card_id,
            "title": self.title,
            "trigger": self.trigger,
            "domain": self.domain,
            "output_type": self.output_type,
            "source_id": self.source_id,
            "investigation_type": self.investigation_type,
            "platform_hints": self.platform_hints,
            "primary_tables": self.primary_tables,
            "investigation_questions": self.investigation_questions,
            "attack_techniques": self.attack_techniques,
            "steps_count": self.steps_count,
            "tags": self.tags,
            "source_file": self.source_file,
        }


# ── Parsing helpers ─────────────────────────────────────────────────────────────

def _make_id(prefix: str, text: str) -> str:
    digest = hashlib.md5(text.encode()).hexdigest()[:8]
    return f"{prefix}-{digest}"


def _extract_tools(text: str) -> List[str]:
    found = []
    t = text.lower()
    for tool_name, keywords in _TOOL_KEYWORDS.items():
        if any(kw in t for kw in keywords):
            found.append(tool_name)
    return found


def _extract_attack_techniques(text: str) -> List[str]:
    return list(dict.fromkeys(_ATTACK_TECHNIQUE_RE.findall(text)))


def _extract_cves(text: str) -> List[str]:
    return list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(text)))


def _infer_domain(scenario_title: str, text: str) -> str:
    t = (scenario_title + " " + text[:500]).lower()
    if any(k in t for k in ["appsec", "sca", "sbom", "dependency", "supply chain",
                              "web app", "container image", "cpe"]):
        return "appsec"
    if any(k in t for k in ["vulnerability management", "vm team", "patch", "prioriti",
                              "remediation", "sprint", "cvss score"]):
        return "vm"
    if any(k in t for k in ["detection", "analytics rule", "kql", "splunk", "elastic",
                              "hunting", "detection engineer", "siem rule", "sigma"]):
        return "detection_eng"
    return "secops"


def _infer_role(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["senior", "threat intel", "detection engineer",
                              "l2", "analyst l2", "architect"]):
        return "senior"
    if any(k in t for k in ["l1", "junior"]):
        return "junior"
    return "mid"


def _infer_difficulty(text: str, attack_techniques: List[str]) -> int:
    t = text.lower()
    if len(attack_techniques) >= 3 or any(k in t for k in ["structural equation",
                                                              "counterfactual",
                                                              "blast radius",
                                                              "do-calculus"]):
        return 3
    if any(k in t for k in ["kill chain", "att&ck", "correlation", "playbook", "langgraph"]):
        return 2
    return 1


def _parse_playbook_source_file(path: Path) -> List[PlaybookCard]:
    """
    Parse a detection_playbooks_by_source.md file into PlaybookCards.

    Format expected:
      ## Data Source: <Name>
      **source_id:** <id>
      **platform_hints:** <comma list>
      **primary_tables:** <comma list>

      ### Playbook: <Title>
      **investigation_type:** <type>
      **trigger:** <description>
      **att&ck:** <T1234, T5678>

      **Investigation Questions:**
      1. <question>
      2. <question>
      ...
    """
    text = path.read_text(encoding="utf-8")
    source_file = path.name
    cards: List[PlaybookCard] = []

    # Regexes for metadata fields
    _meta = lambda key, block: (
        m.group(1).strip()
        if (m := re.search(rf"\*\*{key}:\*\*\s*(.+)", block)) else ""
    )
    _meta_list = lambda key, block: (
        [v.strip() for v in re.split(r"[,/]", m.group(1))]
        if (m := re.search(rf"\*\*{key}:\*\*\s*(.+)", block)) else []
    )
    _nl_questions = lambda block: re.findall(r"^\d+\.\s+(.+)$", block, re.MULTILINE)

    # Split on H2 (data sources)
    h2_re = re.compile(r"^## (.+)$", re.MULTILINE)
    h3_re = re.compile(r"^### Playbook:\s*(.+)$", re.MULTILINE)

    h2_matches = list(h2_re.finditer(text))

    for i, h2 in enumerate(h2_matches):
        ds_title = h2.group(1).strip()
        ds_start = h2.end()
        ds_end = h2_matches[i + 1].start() if i + 1 < len(h2_matches) else len(text)
        ds_block = text[ds_start:ds_end]

        # Skip non-data-source H2s (catalog table, intro, etc.)
        if not ds_title.lower().startswith("data source"):
            continue

        source_id = _meta("source_id", ds_block)
        platform_hints = _meta_list("platform_hints", ds_block)
        primary_tables = _meta_list("primary_tables", ds_block)

        # Split data source block on H3 playbooks
        h3_matches = list(h3_re.finditer(ds_block))

        for j, h3 in enumerate(h3_matches):
            pb_title = h3.group(1).strip()
            pb_start = h3.end()
            pb_end = h3_matches[j + 1].start() if j + 1 < len(h3_matches) else len(ds_block)
            pb_block = ds_block[pb_start:pb_end]

            investigation_type = _meta("investigation_type", pb_block)
            trigger = _meta("trigger", pb_block)
            attack_str = _meta("att&ck", pb_block)
            attack_techniques = [t.strip() for t in attack_str.split(",") if t.strip()]

            questions = _nl_questions(pb_block)

            # Build embedded text: source context + playbook title + all NL questions
            embed_text = (
                f"DATA SOURCE: {ds_title}\n"
                f"SOURCE ID: {source_id}\n"
                f"PLAYBOOK: {pb_title}\n"
                f"INVESTIGATION TYPE: {investigation_type}\n"
                f"TRIGGER: {trigger}\n\n"
                "INVESTIGATION QUESTIONS:\n" +
                "\n".join(f"{k+1}. {q}" for k, q in enumerate(questions))
            )

            card = PlaybookCard(
                card_id=_make_id("pb", source_id + pb_title),
                text=embed_text,
                title=pb_title,
                trigger=trigger,
                domain="detection_eng",
                output_type="nl_questions",
                source_id=source_id,
                investigation_type=investigation_type,
                platform_hints=platform_hints,
                primary_tables=primary_tables,
                investigation_questions=questions,
                attack_techniques=attack_techniques,
                tags=[source_id, investigation_type] + attack_techniques,
                source_file=source_file,
            )
            cards.append(card)

    log.info("Parsed %d playbook cards from %s", len(cards), source_file)
    return cards


def _is_playbook_source_file(path: Path) -> bool:
    """Return True if the file uses the data-source playbook format."""
    try:
        head = path.read_text(encoding="utf-8")[:500]
        return "source_id:" in head or "**source_id:**" in head or "Investigation Questions" in head
    except Exception:
        return False


def _parse_scenario_file(path: Path) -> tuple[List[ScenarioChunk], List[PlaybookCard]]:
    """Parse one markdown file into ScenarioChunks + PlaybookCards."""
    text = path.read_text(encoding="utf-8")
    source_file = path.name
    chunks: List[ScenarioChunk] = []
    cards: List[PlaybookCard] = []

    # ── Split into H2 scenario sections ────────────────────────────────────────
    h2_pattern = re.compile(r"^## (.+)$", re.MULTILINE)
    h3_pattern = re.compile(r"^\*\*Q: (.+?)\*\*$", re.MULTILINE)

    h2_matches = list(h2_pattern.finditer(text))

    for i, h2 in enumerate(h2_matches):
        scenario_title = h2.group(1).strip()
        start = h2.end()
        end = h2_matches[i + 1].start() if i + 1 < len(h2_matches) else len(text)
        section_text = text[start:end]

        # Skip the intro section and quick reference cards
        if any(skip in scenario_title.lower() for skip in
               ["how to use", "the world you", "quick reference", "self-assessment",
                "the alert that", "the monday morning"]):
            # Still extract playbook cards from quick reference sections
            if "quick reference" in scenario_title.lower() or "card" in scenario_title.lower():
                card = PlaybookCard(
                    card_id=_make_id("pb", scenario_title + section_text[:100]),
                    text=f"## {scenario_title}\n{section_text}",
                    title=scenario_title,
                    trigger="quick reference lookup",
                    domain=_infer_domain(scenario_title, section_text),
                    output_type="reference",
                    tags=_extract_tools(section_text) + _extract_attack_techniques(section_text),
                    source_file=source_file,
                )
                cards.append(card)
            continue

        # ── Extract Q&A pairs (H3 bold questions) ──────────────────────────────
        q_matches = list(h3_pattern.finditer(section_text))

        # Determine scenario_id from ordinal
        scenario_idx = i + 1
        prefix = "cve" if "cve" in source_file.lower() else "sentinel"
        scenario_id = f"{prefix}-{scenario_idx:02d}"

        # Infer context from section
        domain = _infer_domain(scenario_title, section_text)

        for j, q_match in enumerate(q_matches):
            question = q_match.group(1).strip()
            q_start = q_match.end()
            q_end = q_matches[j + 1].start() if j + 1 < len(q_matches) else len(section_text)
            answer_text = section_text[q_start:q_end].strip()

            full_text = f"SCENARIO: {scenario_title}\n\nQ: {question}\n\nA: {answer_text}"

            attack_techniques = _extract_attack_techniques(full_text)
            cves = _extract_cves(full_text)
            tools = _extract_tools(full_text)
            has_kql = bool(_KQL_BLOCK_RE.search(answer_text))
            has_queries = has_kql or bool(_SPLUNK_BLOCK_RE.search(answer_text)) or "```" in answer_text

            chunk = ScenarioChunk(
                chunk_id=_make_id(f"{scenario_id}-q{j+1}", question),
                text=full_text,
                scenario_id=scenario_id,
                scenario_title=scenario_title,
                question=question,
                answer_summary=answer_text[:300],
                source_file=source_file,
                domain=domain,
                role_level=_infer_role(scenario_title + " " + question),
                cve_examples=cves,
                attack_techniques=attack_techniques,
                tools_mentioned=tools,
                has_kql=has_kql,
                has_queries=has_queries,
                difficulty=_infer_difficulty(answer_text, attack_techniques),
            )
            chunks.append(chunk)

        # ── Extract playbook cards from decision trees / checklists ────────────
        # Look for code blocks that contain decision trees or checklists
        code_blocks = re.findall(r"```\n(.*?)```", section_text, re.DOTALL)
        for block in code_blocks:
            if any(marker in block for marker in ["→", "☐", "Step ", "Priority", "Decision"]):
                card = PlaybookCard(
                    card_id=_make_id("pb", scenario_id + block[:80]),
                    text=f"PLAYBOOK: {scenario_title}\n\n{block}",
                    title=f"{scenario_title} — Procedure",
                    trigger=_infer_trigger(scenario_title),
                    domain=domain,
                    output_type=_infer_output_type(block),
                    steps_count=block.count("Step ") + block.count("☐"),
                    tags=_extract_tools(block) + ["procedure"],
                    source_file=source_file,
                )
                cards.append(card)

    return chunks, cards


def _infer_trigger(title: str) -> str:
    t = title.lower()
    if "triage" in t or "first" in t or "minute" in t:
        return "new CVE alert received"
    if "kill chain" in t or "att&ck" in t:
        return "analyzing attack path for a CVE"
    if "cpe" in t or "affected" in t:
        return "determining if systems are affected"
    if "priority" in t or "calcul" in t:
        return "prioritising vulnerability remediation"
    if "detection" in t or "query" in t or "kql" in t:
        return "writing detection rules"
    if "control" in t or "compensat" in t:
        return "patching is delayed, need compensating controls"
    if "execut" in t or "manager" in t or "brief" in t:
        return "briefing management or reporting upward"
    return "general security engineering task"


def _infer_output_type(block: str) -> str:
    if "☐" in block:
        return "checklist"
    if "→" in block and ("YES" in block or "NO" in block):
        return "decision"
    if "| " in block:
        return "reference"
    if "Step " in block:
        return "procedure"
    return "reference"


# ── Qdrant upsert ───────────────────────────────────────────────────────────────

def _upsert_to_qdrant(
    chunks: List[ScenarioChunk],
    cards: List[PlaybookCard],
    dry_run: bool = False,
) -> dict:
    """Embed and upsert all chunks/cards to Qdrant."""
    from asteraskills.storage.vector_store import VectorStoreClient
    from asteraskills.storage.collections import DetectionCollections

    if dry_run:
        log.info("[DRY RUN] Would upsert %d scenario chunks + %d playbook cards",
                 len(chunks), len(cards))
        return {"chunks_upserted": 0, "cards_upserted": 0, "dry_run": True}

    client = VectorStoreClient()

    # ── Scenario chunks ─────────────────────────────────────────────────────────
    chunk_docs = [
        {"id": c.chunk_id, "text": c.text, "metadata": c.to_qdrant_payload()}
        for c in chunks
    ]
    chunks_upserted = 0
    if chunk_docs:
        import asyncio
        asyncio.run(client.add_documents(
            collection_name=DetectionCollections.SCENARIOS,
            documents=chunk_docs,
        ))
        chunks_upserted = len(chunk_docs)
        log.info("Upserted %d scenario chunks → %s",
                 chunks_upserted, DetectionCollections.SCENARIOS)

    # ── Playbook cards ──────────────────────────────────────────────────────────
    card_docs = [
        {"id": c.card_id, "text": c.text, "metadata": c.to_qdrant_payload()}
        for c in cards
    ]
    cards_upserted = 0
    if card_docs:
        asyncio.run(client.add_documents(
            collection_name=DetectionCollections.PLAYBOOKS,
            documents=card_docs,
        ))
        cards_upserted = len(card_docs)
        log.info("Upserted %d playbook cards → %s",
                 cards_upserted, DetectionCollections.PLAYBOOKS)

    return {"chunks_upserted": chunks_upserted, "cards_upserted": cards_upserted}


# ── Public entry point ──────────────────────────────────────────────────────────

def ingest_detection_scenarios(
    files: Optional[List[Path]] = None,
    playbook_files: Optional[List[Path]] = None,
    dry_run: bool = False,
) -> dict:
    """
    Parse detection scenario + playbook-by-source markdown files and upsert to Qdrant.

    Scenario files (Q&A format) → detection_scenarios collection
    Playbook files (NL-question format) → detection_playbooks collection

    Args:
        files:          Paths to Q&A scenario markdown files.
        playbook_files: Paths to source-based playbook markdown files.
        dry_run:        If True, parse and log but do not write to Qdrant.

    Returns:
        {"chunks_upserted": int, "cards_upserted": int, "dry_run": bool}
    """
    # ── Scenario Q&A files ──────────────────────────────────────────────────────
    scenario_sources = files or [p for p in DEFAULT_SCENARIO_FILES if p.exists()]

    # ── Playbook-by-source files — route through dedicated parser ───────────────
    pb_sources = playbook_files or [p for p in DEFAULT_PLAYBOOK_FILES if p.exists()]

    if not scenario_sources and not pb_sources:
        log.warning("No input files found. Pass --files / --playbook-files or ensure causalgraphs dir exists.")
        return {"chunks_upserted": 0, "cards_upserted": 0, "error": "no_files"}

    all_chunks: List[ScenarioChunk] = []
    all_cards: List[PlaybookCard] = []

    for path in scenario_sources:
        log.info("Parsing scenario file: %s", path)
        chunks, cards = _parse_scenario_file(path)
        all_chunks.extend(chunks)
        all_cards.extend(cards)
        log.info("  → %d Q&A chunks, %d legacy playbook cards", len(chunks), len(cards))

    for path in pb_sources:
        log.info("Parsing playbook-source file: %s", path)
        if _is_playbook_source_file(path):
            pb_cards = _parse_playbook_source_file(path)
            all_cards.extend(pb_cards)
            log.info("  → %d NL-question playbook cards", len(pb_cards))
        else:
            # Fallback: treat as scenario file
            chunks, cards = _parse_scenario_file(path)
            all_chunks.extend(chunks)
            all_cards.extend(cards)

    log.info("Total: %d Q&A chunks, %d playbook cards", len(all_chunks), len(all_cards))
    return _upsert_to_qdrant(all_chunks, all_cards, dry_run=dry_run)


# ── CLI ─────────────────────────────────────────────────────────────────────────

def _cli():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    p = argparse.ArgumentParser(
        description="Ingest detection scenario guides into Qdrant.",
    )
    p.add_argument(
        "--files", nargs="+", type=Path,
        help="Q&A scenario markdown files. Defaults to cve_detection_scenarios.md + other_detection_usecases.md",
    )
    p.add_argument(
        "--playbook-files", nargs="+", type=Path, dest="playbook_files",
        help="Playbook-by-source markdown files. Defaults to detection_playbooks_by_source.md",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Parse and log stats without writing to Qdrant.",
    )
    args = p.parse_args()

    result = ingest_detection_scenarios(
        files=args.files,
        playbook_files=args.playbook_files,
        dry_run=args.dry_run,
    )
    print(f"\nIngestion complete:")
    print(f"  Scenario chunks upserted : {result.get('chunks_upserted', 0)}")
    print(f"  Playbook cards upserted  : {result.get('cards_upserted', 0)}")
    if result.get("dry_run"):
        print("  (dry run — nothing written)")


if __name__ == "__main__":
    _cli()
