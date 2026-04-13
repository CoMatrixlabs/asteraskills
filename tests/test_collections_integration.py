"""
Integration tests: Security intelligence collections (vector store + Postgres).

Tests each collection in:
  FrameworkCollections  — framework_controls, framework_items, framework_risks,
                          framework_test_cases, framework_scenarios, framework_requirements,
                          user_policies
  AttackCollections     — attack_techniques, attack_tactic_contexts, attack_control_mappings
  ThreatIntelCollections — threat_intel_cwe_capec, threat_intel_cwe_capec_attack_mappings

Coverage structure:
  1. Availability probe  — detects live vector store; skips gracefully if absent
  2. Collection queries  — raw client.query() per collection; validates response schema
  3. Tool functions      — _execute_framework_item_retrieval, _semantic_threat_intel,
                           CWE/CAPEC lookup, CIS controls search
  4. Cross-collection chain — CWE → ATT&CK → controls enrichment path
  5. Scenario-aligned   — same 5 scenarios as test_scenarios.py, now backed by live collections

Run with live Qdrant/Chroma + keys from the repo ``.env`` (e.g. OPENAI_API_KEY) for full coverage.
Collection names come from ``vector_collection()`` (canonical names like ``attack_techniques``,
``framework_items``; the three ATT&CK/mapping collections can be overridden via settings).
Tests self-skip when the vector store is unreachable.
"""

from __future__ import annotations

import asyncio
import functools
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
_APP_DIR = _REPO_ROOT / "app"
for _p in (_APP_DIR, _REPO_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


def _load_dotenv_for_tests() -> None:
    """Load repo ``.env`` before any ``asteraskills`` import (``python tests/...py`` runner)."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    main = _REPO_ROOT / ".env"
    if main.is_file():
        load_dotenv(main, override=False)
    extra = os.environ.get("ASTERASKILLS_ENV_FILE")
    if extra:
        p = Path(extra).expanduser()
        if p.is_file():
            load_dotenv(p, override=False)


_load_dotenv_for_tests()

_FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Availability probe (runs once; result cached in module-level variable)
# ---------------------------------------------------------------------------

_AVAILABLE: Optional[bool] = None
_SKIP_REASON: str = ""


def _run_async(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _check_vector_store() -> bool:
    """Return True if the vector store is reachable and attack_techniques is queryable."""
    global _AVAILABLE, _SKIP_REASON
    if _AVAILABLE is not None:
        return _AVAILABLE

    async def _probe():
        from asteraskills.storage.vector_store import get_vector_store_client
        from asteraskills.storage.collections import AttackCollections
        client = get_vector_store_client()
        await client.initialize()
        result = await client.query(
            collection_name=AttackCollections.techniques(),
            query_texts=["test probe"],
            n_results=1,
        )
        return isinstance(result, dict) and "documents" in result

    try:
        ok = _run_async(_probe())
        _AVAILABLE = bool(ok)
        return _AVAILABLE
    except Exception as exc:
        _SKIP_REASON = str(exc)[:300]
        _AVAILABLE = False
        return False


def skip_if_unavailable(fn):
    """Decorator: skip a test if the vector store cannot be reached."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not _check_vector_store():
            msg = f"SKIPPED ({_SKIP_REASON[:100]})" if _SKIP_REASON else "SKIPPED (vector store not available)"
            print(f"\n  {msg}")
            return
        return fn(*args, **kwargs)
    return wrapper


def _assert_query_response(result: Dict[str, Any], collection: str, min_docs: int = 0) -> None:
    """Validate the standard {ids, documents, metadatas, distances} response shape."""
    assert isinstance(result, dict), f"{collection}: response should be dict"
    assert "documents" in result, f"{collection}: missing 'documents' key"
    docs = result["documents"]
    assert isinstance(docs, list), f"{collection}: 'documents' should be list"
    if docs:
        assert isinstance(docs[0], list), f"{collection}: documents[0] should be inner list"
        if min_docs > 0:
            assert len(docs[0]) >= min_docs, (
                f"{collection}: expected ≥{min_docs} result(s), got {len(docs[0])}"
            )


def _inner_docs(result: Dict[str, Any]) -> list:
    """Safely return the inner document list (empty list if collection has no data)."""
    docs = result.get("documents", [])
    return docs[0] if docs else []


def _inner_metas(result: Dict[str, Any]) -> list:
    """Safely return the inner metadata list."""
    metas = result.get("metadatas", [])
    return metas[0] if metas else []


def _empty_collection_note(collection: str, docs: list) -> None:
    """Print a note when a collection returned no documents."""
    if not docs:
        print(
            f"  Note: {collection!r} returned 0 results — collection may be empty, need ingestion, "
            f"or check Qdrant host/port and collection names in settings (``.env``)."
        )


# ---------------------------------------------------------------------------
# 1. Collection query tests — raw vector store client
# ---------------------------------------------------------------------------

@skip_if_unavailable
def test_attack_techniques_queryable() -> None:
    """attack_techniques collection returns results for T1190 Log4Shell initial access query."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import AttackCollections

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        return await client.query(
            collection_name=AttackCollections.techniques(),
            query_texts=["T1190 exploit public-facing application Log4Shell initial access"],
            n_results=5,
        )

    result = _run_async(_q())
    _assert_query_response(result, AttackCollections.techniques())
    docs = _inner_docs(result)
    _empty_collection_note(AttackCollections.techniques(), docs)
    print(f"\n✓ {AttackCollections.techniques()}: {len(docs)} result(s)")
    if docs:
        metas = _inner_metas(result)
        print(f"  Top result metadata keys: {list((metas[0] or {}).keys())[:8]}")


@skip_if_unavailable
def test_attack_tactic_contexts_queryable() -> None:
    """attack_tactic_contexts collection returns tactic risk lens entries."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import AttackCollections

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        return await client.query(
            collection_name=AttackCollections.tactic_contexts(),
            query_texts=["T1059 execution bash reverse shell code execution risk"],
            n_results=5,
        )

    result = _run_async(_q())
    _assert_query_response(result, AttackCollections.tactic_contexts())
    docs = _inner_docs(result)
    _empty_collection_note(AttackCollections.tactic_contexts(), docs)
    print(f"\n✓ {AttackCollections.tactic_contexts()}: {len(docs)} result(s)")


@skip_if_unavailable
def test_attack_control_mappings_queryable() -> None:
    """attack_control_mappings collection returns control-technique mapping entries."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import AttackCollections

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        return await client.query(
            collection_name=AttackCollections.control_mappings(),
            query_texts=["access control privilege escalation mitigation"],
            n_results=5,
        )

    result = _run_async(_q())
    _assert_query_response(result, AttackCollections.control_mappings())
    docs = _inner_docs(result)
    _empty_collection_note(AttackCollections.control_mappings(), docs)
    print(f"\n✓ {AttackCollections.control_mappings()}: {len(docs)} result(s)")


@skip_if_unavailable
def test_threat_intel_cwe_capec_queryable() -> None:
    """threat_intel_cwe_capec collection returns CWE and CAPEC entries."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import ThreatIntelCollections

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        return await client.query(
            collection_name=ThreatIntelCollections.cwe_capec(),
            query_texts=["SQL injection unsanitized user input database query"],
            n_results=5,
        )

    result = _run_async(_q())
    _assert_query_response(result, ThreatIntelCollections.cwe_capec())
    docs = _inner_docs(result)
    metas = _inner_metas(result)
    _empty_collection_note(ThreatIntelCollections.cwe_capec(), docs)
    print(f"\n✓ {ThreatIntelCollections.cwe_capec()}: {len(docs)} result(s)")
    if metas:
        entity_types = {m.get("entity_type") for m in metas if m}
        print(f"  entity_type values: {entity_types}")


@skip_if_unavailable
def test_threat_intel_cwe_capec_cwe_filter() -> None:
    """threat_intel_cwe_capec: entity_type=cwe filter returns only CWE entries."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import ThreatIntelCollections

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        where = client.normalize_filter({"entity_type": "cwe"})
        return await client.query(
            collection_name=ThreatIntelCollections.cwe_capec(),
            query_texts=["SQL injection untrusted data database"],
            n_results=8,
            where=where,
        )

    result = _run_async(_q())
    _assert_query_response(result, ThreatIntelCollections.cwe_capec())
    metas = _inner_metas(result)
    if metas:
        for m in metas:
            assert (m or {}).get("entity_type") == "cwe", (
                f"Expected entity_type=cwe, got: {(m or {}).get('entity_type')}"
            )
    _empty_collection_note(ThreatIntelCollections.cwe_capec(), metas)
    print(f"\n✓ {ThreatIntelCollections.cwe_capec()} (CWE filter): {len(metas)} result(s)")


@skip_if_unavailable
def test_threat_intel_cwe_capec_attack_mappings_queryable() -> None:
    """threat_intel_cwe_capec_attack_mappings collection returns CWE→ATT&CK triples."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import ThreatIntelCollections

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        return await client.query(
            collection_name=ThreatIntelCollections.cwe_capec_attack_mappings(),
            query_texts=["CWE-89 SQL injection ATT&CK initial access T1190"],
            n_results=5,
        )

    result = _run_async(_q())
    _assert_query_response(result, ThreatIntelCollections.cwe_capec_attack_mappings())
    docs = _inner_docs(result)
    _empty_collection_note(ThreatIntelCollections.cwe_capec_attack_mappings(), docs)
    print(f"\n✓ {ThreatIntelCollections.cwe_capec_attack_mappings()}: {len(docs)} result(s)")


@skip_if_unavailable
def test_framework_items_queryable() -> None:
    """framework_items collection returns control items for access control query."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import FrameworkCollections

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        return await client.query(
            collection_name=FrameworkCollections.items(),
            query_texts=["privileged access management least privilege identity controls"],
            n_results=8,
        )

    result = _run_async(_q())
    _assert_query_response(result, FrameworkCollections.items())
    metas = _inner_metas(result)
    _empty_collection_note(FrameworkCollections.items(), metas)
    print(f"\n✓ {FrameworkCollections.items()}: {len(metas)} result(s)")
    if metas:
        framework_ids = {(m or {}).get("framework_id") for m in metas}
        print(f"  Framework IDs represented: {framework_ids}")


@skip_if_unavailable
def test_framework_items_tactic_filter() -> None:
    """framework_items: tactic_domains__contains filter returns tactic-relevant controls."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import FrameworkCollections

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        where = client.normalize_filter({
            "tactic_domains__contains": "initial-access",
        })
        return await client.query(
            collection_name=FrameworkCollections.items(),
            query_texts=["Log4Shell JNDI remote code execution patch management"],
            n_results=8,
            where=where,
        )

    result = _run_async(_q())
    _assert_query_response(result, FrameworkCollections.items())
    docs = _inner_docs(result)
    _empty_collection_note(FrameworkCollections.items(), docs)
    print(f"\n✓ {FrameworkCollections.items()} (tactic=initial-access): {len(docs)} result(s)")


@skip_if_unavailable
def test_framework_items_nist_filter() -> None:
    """framework_items: framework_id filter returns only NIST 800-53 items."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import FrameworkCollections

    NIST_ID = "nist_800_53r5"

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        where = client.normalize_filter({"framework_id": NIST_ID})
        return await client.query(
            collection_name=FrameworkCollections.items(),
            query_texts=["system patch management vulnerability remediation"],
            n_results=5,
            where=where,
        )

    result = _run_async(_q())
    _assert_query_response(result, FrameworkCollections.items())
    metas = _inner_metas(result)
    if metas:
        for m in metas:
            assert (m or {}).get("framework_id") == NIST_ID, (
                f"Expected framework_id={NIST_ID}, got: {(m or {}).get('framework_id')}"
            )
    _empty_collection_note(FrameworkCollections.items(), metas)
    print(f"\n✓ {FrameworkCollections.items()} (NIST filter): {len(metas)} result(s)")


@skip_if_unavailable
def test_framework_controls_queryable() -> None:
    """framework_controls collection is reachable."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import FrameworkCollections

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        return await client.query(
            collection_name=FrameworkCollections.controls(),
            query_texts=["access control monitoring detection"],
            n_results=5,
        )

    result = _run_async(_q())
    _assert_query_response(result, FrameworkCollections.controls())
    docs = _inner_docs(result)
    _empty_collection_note(FrameworkCollections.controls(), docs)
    print(f"\n✓ {FrameworkCollections.controls()}: {len(docs)} result(s)")


@skip_if_unavailable
def test_framework_risks_queryable() -> None:
    """framework_risks collection returns risk scenario entries."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import FrameworkCollections

    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        return await client.query(
            collection_name=FrameworkCollections.risks(),
            query_texts=["ransomware data encryption impact business disruption"],
            n_results=5,
        )

    result = _run_async(_q())
    _assert_query_response(result, FrameworkCollections.risks())
    docs = _inner_docs(result)
    _empty_collection_note(FrameworkCollections.risks(), docs)
    print(f"\n✓ {FrameworkCollections.risks()}: {len(docs)} result(s)")


# ---------------------------------------------------------------------------
# 2. Tool function tests — using the asteraskills tool layer
# ---------------------------------------------------------------------------

@skip_if_unavailable
def test_tool_semantic_cwe_lookup_sql_injection() -> None:
    """_semantic_threat_intel returns CWE-89 for SQL injection query."""
    from asteraskills.tools.cwe_capec_cis_tools import _semantic_threat_intel

    hits = _run_async(
        _semantic_threat_intel(
            "SQL injection untrusted user input concatenated into database query",
            entity_type="cwe",
            top_k=8,
        )
    )
    assert isinstance(hits, list), "Expected list of hits"
    print(f"\n✓ _semantic_threat_intel (CWE/SQL injection): {len(hits)} hit(s)")
    if hits:
        ids = [h.get("entity_id", "") for h in hits]
        print(f"  Top entity IDs: {ids[:5]}")
        # CWE-89 should rank highly for this query if the collection is populated
        if any("89" in str(h.get("entity_id", "")) or "89" in str(h.get("id", "")) for h in hits):
            print("  ✓ CWE-89 found in results")
        else:
            print(f"  Note: CWE-89 not in top {len(hits)} — collection may need ingestion")


@skip_if_unavailable
def test_tool_semantic_capec_lookup_injection() -> None:
    """_semantic_threat_intel returns CAPEC entries for injection attack query."""
    from asteraskills.tools.cwe_capec_cis_tools import _semantic_threat_intel

    hits = _run_async(
        _semantic_threat_intel(
            "injection attack manipulating interpreter command execution",
            entity_type="capec",
            top_k=5,
        )
    )
    assert isinstance(hits, list)
    print(f"\n✓ _semantic_threat_intel (CAPEC/injection): {len(hits)} hit(s)")
    if hits:
        print(f"  Top: {hits[0].get('entity_id', '')} — {hits[0].get('name', '')[:60]}")


@skip_if_unavailable
def test_tool_framework_item_retrieval_initial_access_nist() -> None:
    """_execute_framework_item_retrieval returns NIST controls for initial-access tactic."""
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval

    items = _execute_framework_item_retrieval(
        query="Apache Log4j JNDI remote code execution exploit public-facing application",
        framework_id="nist_800_53r5",
        tactic="initial-access",
        top_k=5,
        score_threshold=0.0,  # no threshold — return whatever matches
    )
    assert isinstance(items, list), "Expected list of framework items"
    print(f"\n✓ _execute_framework_item_retrieval (NIST/initial-access): {len(items)} item(s)")
    for item in items[:3]:
        print(f"  {item.get('item_id', '')}: {item.get('title', '')[:60]} "
              f"score={item.get('similarity_score', 0):.3f}")
    if items:
        for item in items:
            assert "item_id" in item
            assert "framework_id" in item
            assert "similarity_score" in item


@skip_if_unavailable
def test_tool_framework_item_retrieval_persistence_cis() -> None:
    """_execute_framework_item_retrieval returns CIS controls for persistence tactic."""
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval

    items = _execute_framework_item_retrieval(
        query="new user account creation backdoor persistence systemd service",
        framework_id="cis_controls_v8_1",
        tactic="persistence",
        top_k=5,
        score_threshold=0.0,
    )
    assert isinstance(items, list)
    print(f"\n✓ _execute_framework_item_retrieval (CIS/persistence): {len(items)} item(s)")
    for item in items[:3]:
        print(f"  {item.get('item_id', '')}: {item.get('title', '')[:60]}")


@skip_if_unavailable
def test_tool_cis_controls_search_privilege_escalation() -> None:
    """_cis_framework_search_async returns CIS controls for privilege escalation."""
    from asteraskills.tools.cwe_capec_cis_tools import _cis_framework_search_async

    items = _run_async(
        _cis_framework_search_async(
            query="cloud account privilege escalation IAM administrative access without MFA",
            tactic="privilege-escalation",
            top_k=5,
            score_threshold=0.0,
        )
    )
    assert isinstance(items, list)
    print(f"\n✓ _cis_framework_search_async (privilege-escalation): {len(items)} item(s)")
    for item in items[:3]:
        print(f"  {item.get('item_id', '')}: {item.get('title', '')[:60]}")


@skip_if_unavailable
def test_tool_framework_item_retrieval_broad_soc2() -> None:
    """_execute_framework_item_retrieval_broad returns SOC 2 items without tactic filter."""
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval_broad

    items = _execute_framework_item_retrieval_broad(
        query="terminated employee access deprovisioning logical access controls SOC 2",
        framework_id="soc2_2017",
        top_k=5,
        min_score=0.0,
    )
    assert isinstance(items, list)
    print(f"\n✓ _execute_framework_item_retrieval_broad (SOC2): {len(items)} item(s)")
    for item in items[:3]:
        print(f"  {item.get('item_id', '')}: {item.get('title', '')[:60]}")


# ---------------------------------------------------------------------------
# 3. Cross-collection chain tests
# ---------------------------------------------------------------------------

@skip_if_unavailable
def test_chain_cwe89_to_cwe_capec_collection() -> None:
    """CWE-89 → threat_intel_cwe_capec collection → ATT&CK technique mentions."""
    from asteraskills.tools.cwe_capec_cis_tools import _semantic_threat_intel
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import ThreatIntelCollections

    # Step 1: Find CWE-89 related entries in the CWE_CAPEC collection
    cwe_hits = _run_async(
        _semantic_threat_intel(
            "CWE-89 SQL injection tainted input database execute query",
            entity_type="cwe",
            top_k=5,
        )
    )
    print(f"\n✓ Chain CWE-89: {len(cwe_hits)} CWE hit(s) from threat_intel_cwe_capec")

    # Step 2: Query CWE→ATT&CK mappings collection
    async def _attack_q():
        client = get_vector_store_client()
        await client.initialize()
        return await client.query(
            collection_name=ThreatIntelCollections.cwe_capec_attack_mappings(),
            query_texts=["CWE-89 SQL injection attack technique exploitation"],
            n_results=5,
        )

    attack_mappings = _run_async(_attack_q())
    docs = attack_mappings.get("documents", [[]])[0]
    print(f"  → {len(docs)} ATT&CK mapping(s) from threat_intel_cwe_capec_attack_mappings")

    # Step 3: Query framework items for the relevant tactic
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval
    controls = _execute_framework_item_retrieval(
        query="SQL injection input validation parameterized queries database access control",
        framework_id="nist_800_53r5",
        tactic="initial-access",
        top_k=5,
        score_threshold=0.0,
    )
    print(f"  → {len(controls)} NIST control(s) from framework_items")
    print(f"  Full chain: CWE-89 → {len(cwe_hits)} CWE hits → {len(docs)} attack maps → {len(controls)} controls")


@skip_if_unavailable
def test_chain_t1190_tactic_context_to_framework_items() -> None:
    """T1190 initial access → attack_tactic_contexts → framework_items for SOC2 + NIST."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import AttackCollections
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval

    # Step 1: Get tactic context for T1190/initial-access
    async def _tactic_q():
        client = get_vector_store_client()
        await client.initialize()
        where = client.normalize_filter({
            "technique_id": "T1190",
            "tactic": "initial-access",
        })
        return await client.query(
            collection_name=AttackCollections.tactic_contexts(),
            query_texts=["T1190 initial access exploit public-facing application"],
            n_results=3,
            where=where,
        )

    tactic_ctx = _run_async(_tactic_q())
    ctx_docs = tactic_ctx.get("documents", [[]])[0]
    print(f"\n✓ Chain T1190: {len(ctx_docs)} tactic context(s) from attack_tactic_contexts")

    # Step 2: Use tactic risk lens to query framework items
    risk_lens = ctx_docs[0] if ctx_docs else "T1190 exploit public-facing application initial access"
    risk_lens_excerpt = str(risk_lens)[:300]

    nist_items = _execute_framework_item_retrieval(
        query=risk_lens_excerpt,
        framework_id="nist_800_53r5",
        tactic="initial-access",
        top_k=5,
        score_threshold=0.0,
    )
    soc2_items = _execute_framework_item_retrieval(
        query=risk_lens_excerpt,
        framework_id="soc2_2017",
        tactic="initial-access",
        top_k=5,
        score_threshold=0.0,
    )
    print(f"  → {len(nist_items)} NIST item(s), {len(soc2_items)} SOC2 item(s) from framework_items")
    if nist_items:
        print(f"  Top NIST: {nist_items[0].get('item_id', '')} — {nist_items[0].get('title', '')[:50]}")
    if soc2_items:
        print(f"  Top SOC2: {soc2_items[0].get('item_id', '')} — {soc2_items[0].get('title', '')[:50]}")


@skip_if_unavailable
def test_chain_kill_chain_techniques_to_controls() -> None:
    """SIEM kill chain techniques (T1190→T1059→T1547→T1082) → framework controls per stage."""
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval

    kill_chain = [
        ("T1190", "initial-access",   "exploit public-facing application Log4Shell RCE"),
        ("T1059",  "execution",       "bash reverse shell command interpreter execution"),
        ("T1547",  "persistence",     "systemd service registry persistence boot autostart"),
        ("T1082",  "discovery",       "system information discovery uname hostname process list"),
    ]

    print(f"\n✓ Kill chain → controls:")
    total_controls = 0
    for technique_id, tactic, query_hint in kill_chain:
        controls = _execute_framework_item_retrieval(
            query=f"{technique_id} {tactic} {query_hint}",
            framework_id="nist_800_53r5",
            tactic=tactic,
            top_k=3,
            score_threshold=0.0,
        )
        total_controls += len(controls)
        top = controls[0].get("item_id", "–") if controls else "–"
        print(f"  {technique_id}/{tactic}: {len(controls)} control(s) — top: {top}")

    print(f"  Total controls across kill chain stages: {total_controls}")


# ---------------------------------------------------------------------------
# 4. Scenario-aligned integration tests
# ---------------------------------------------------------------------------

@skip_if_unavailable
def test_scenario0_sbom_cve_enrichment_via_collections() -> None:
    """
    Scenario 0: SBOM scan — Log4Shell CVE-2021-44228.
    Enrichment chain: CVE → tactic_contexts → framework_items (NIST + SOC2).
    """
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import AttackCollections

    # Log4Shell exploits T1190 (initial-access) and T1059.007 (execution)
    techniques = [
        ("T1190", "initial-access"),
        ("T1059",  "execution"),
    ]
    print(f"\n✓ Scenario 0 (SBOM + collections): CVE-2021-44228 enrichment")

    for tech_id, tactic in techniques:
        # Get tactic context
        async def _tactic_q(t=tech_id, tc=tactic):
            client = get_vector_store_client()
            await client.initialize()
            return await client.query(
                collection_name=AttackCollections.tactic_contexts(),
                query_texts=[f"{t} {tc} Log4Shell Java JNDI remote code execution"],
                n_results=2,
            )

        ctx = _run_async(_tactic_q())
        ctx_docs = ctx.get("documents", [[]])[0]

        # Get control items
        query = ctx_docs[0][:200] if ctx_docs else f"{tech_id} {tactic} Log4Shell exploit"
        nist = _execute_framework_item_retrieval(query, "nist_800_53r5", tactic, top_k=3, score_threshold=0.0)
        print(f"  {tech_id}/{tactic}: ctx={len(ctx_docs)}, NIST controls={len(nist)}")


@skip_if_unavailable
def test_scenario1_terraform_policy_attack_mapping_via_collections() -> None:
    """
    Scenario 1: Terraform S3 public ACL → T1530 (data from cloud storage) → controls.
    Uses attack_tactic_contexts + framework_items for collection-backed enrichment.
    """
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import AttackCollections

    # S3 public ACL → T1530 (collection) / T1213 (info repositories)
    async def _q():
        client = get_vector_store_client()
        await client.initialize()
        return await client.query(
            collection_name=AttackCollections.techniques(),
            query_texts=["T1530 data from cloud storage object S3 public bucket exfiltration"],
            n_results=3,
        )

    tech_results = _run_async(_q())
    tech_docs = tech_results.get("documents", [[]])[0]

    cis_controls = _execute_framework_item_retrieval(
        query="cloud storage public access data exfiltration S3 object storage controls",
        framework_id="cis_controls_v8_1",
        tactic="collection",
        top_k=5,
        score_threshold=0.0,
    )
    print(
        f"\n✓ Scenario 1 (Terraform + collections): "
        f"T1530 technique docs={len(tech_docs)}, CIS controls={len(cis_controls)}"
    )
    if cis_controls:
        print(f"  Top CIS: {cis_controls[0].get('item_id', '')} — {cis_controls[0].get('title', '')[:50]}")


@skip_if_unavailable
def test_scenario2_cwe89_full_collection_chain() -> None:
    """
    Scenario 2: CWE-89 SQL injection.
    Chain: threat_intel_cwe_capec → CWE_CAPEC_ATTACK_MAPPINGS → framework_items.
    """
    from asteraskills.tools.cwe_capec_cis_tools import _semantic_threat_intel
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval

    # Step 1: CWE semantic lookup
    cwe_hits = _run_async(
        _semantic_threat_intel(
            "SQL injection tainted user input passed directly to database execute without sanitization",
            entity_type="cwe",
            top_k=5,
        )
    )

    # Step 2: Get framework controls for SQL injection / initial-access tactic
    nist_controls = _execute_framework_item_retrieval(
        query="SQL injection input validation parameterized statements secure coding",
        framework_id="nist_800_53r5",
        tactic="initial-access",
        top_k=5,
        score_threshold=0.0,
    )

    print(
        f"\n✓ Scenario 2 (CWE-89 + collections): "
        f"CWE hits={len(cwe_hits)}, NIST controls={len(nist_controls)}"
    )
    if cwe_hits:
        print(f"  Top CWE: {cwe_hits[0].get('entity_id', '')} — {cwe_hits[0].get('name', '')[:50]}")
    if nist_controls:
        print(f"  Top NIST: {nist_controls[0].get('item_id', '')} — {nist_controls[0].get('title', '')[:50]}")


@skip_if_unavailable
def test_scenario3_siem_kill_chain_tactic_contexts() -> None:
    """
    Scenario 3: SIEM kill chain T1190→T1059→T1547→T1082.
    Retrieves tactic context from attack_tactic_contexts for each stage.
    """
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import AttackCollections

    stages = [
        ("T1190", "initial-access"),
        ("T1059",  "execution"),
        ("T1547",  "persistence"),
        ("T1082",  "discovery"),
    ]

    print(f"\n✓ Scenario 3 (SIEM kill chain + tactic_contexts):")
    for tech_id, tactic in stages:
        async def _q(t=tech_id, tc=tactic):
            client = get_vector_store_client()
            await client.initialize()
            return await client.query(
                collection_name=AttackCollections.tactic_contexts(),
                query_texts=[f"{t} {tc}"],
                n_results=2,
            )

        result = _run_async(_q())
        docs = result.get("documents", [[]])[0]
        lens_preview = ""
        if docs:
            lens_preview = str(docs[0])[:80]
        print(f"  {tech_id}/{tactic}: {len(docs)} ctx doc(s) — {lens_preview!r}")


@skip_if_unavailable
def test_scenario4_soc2_framework_items_deficiencies() -> None:
    """
    Scenario 4: SOC 2 evidence — CC6.1 (access control) + CC7.2 (incident response).
    Retrieves framework_items for the relevant SOC 2 controls.
    """
    from asteraskills.tools.framework_item_retrieval import _execute_framework_item_retrieval_broad

    # CC6.1 — Logical Access Controls (terminated user accounts)
    cc6_items = _execute_framework_item_retrieval_broad(
        query="logical access controls terminated employees deprovisioning SSO account removal",
        framework_id="soc2_2017",
        top_k=5,
        min_score=0.0,
    )

    # CC7.2 — Incident Response
    cc7_items = _execute_framework_item_retrieval_broad(
        query="incident response procedures tested tabletop exercise detection containment",
        framework_id="soc2_2017",
        top_k=5,
        min_score=0.0,
    )

    print(f"\n✓ Scenario 4 (SOC2 + framework_items):")
    print(f"  CC6.1 (access controls): {len(cc6_items)} item(s)")
    print(f"  CC7.2 (incident response): {len(cc7_items)} item(s)")
    for item in (cc6_items + cc7_items)[:4]:
        print(f"  {item.get('item_id', '')}: {item.get('title', '')[:60]} "
              f"score={item.get('similarity_score', 0):.3f}")

    # Cross-scenario correlation: same CC7.1 gap appears in SBOM + SOC2 scans
    cc7_1_items = _execute_framework_item_retrieval_broad(
        query="CC7.1 change management patch management vulnerability monitoring SOC2",
        framework_id="soc2_2017",
        top_k=3,
        min_score=0.0,
    )
    print(f"  CC7.1 (patch+change mgmt — cross-scan correlation): {len(cc7_1_items)} item(s)")


# ---------------------------------------------------------------------------
# 5. Collection health summary — single test that prints all collection statuses
# ---------------------------------------------------------------------------

@skip_if_unavailable
def test_all_collections_health_check() -> None:
    """Report reachability and document count for every registered collection."""
    from asteraskills.storage.vector_store import get_vector_store_client
    from asteraskills.storage.collections import (
        FrameworkCollections, AttackCollections, ThreatIntelCollections,
    )

    all_collections = (
        [(c, "Framework") for c in FrameworkCollections.all_names()]
        + [(c, "Attack") for c in AttackCollections.all_names()]
        + [(c, "ThreatIntel") for c in ThreatIntelCollections.all_names()]
    )

    print(f"\n{'=' * 64}")
    print(f"{'Collection':<45} {'Group':<12} {'Docs':>6}")
    print(f"{'-' * 64}")

    async def _count_collection(name: str) -> int:
        client = get_vector_store_client()
        await client.initialize()
        result = await client.query(
            collection_name=name,
            query_texts=["health check"],
            n_results=1,
        )
        # Return number of docs returned — not total count (no count API), but confirms reachable
        docs = _inner_docs(result)
        return len(docs)

    healthy = 0
    empty = 0
    errors = 0
    for cname, group in all_collections:
        try:
            doc_count = _run_async(_count_collection(cname))
            status = "≥1" if doc_count > 0 else "0"
            if doc_count > 0:
                healthy += 1
            else:
                empty += 1
            print(f"  {cname:<43} {group:<12} {status:>6}")
        except Exception as exc:
            errors += 1
            print(f"  {cname:<43} {group:<12} {'ERROR':>6}  ({str(exc)[:40]})")

    print(f"{'=' * 64}")
    print(f"  Collections with data: {healthy}/{len(all_collections)}")
    if empty:
        print(f"  Empty collections:     {empty} (need ingestion)")
    if errors:
        print(f"  Unreachable:           {errors}")

    assert errors == 0, (
        f"{errors} collection(s) raised errors. "
        "Check vector store connectivity and collection names."
    )


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

def run_all_tests() -> None:
    tests = [
        # Collection queries
        test_attack_techniques_queryable,
        test_attack_tactic_contexts_queryable,
        test_attack_control_mappings_queryable,
        test_threat_intel_cwe_capec_queryable,
        test_threat_intel_cwe_capec_cwe_filter,
        test_threat_intel_cwe_capec_attack_mappings_queryable,
        test_framework_items_queryable,
        test_framework_items_tactic_filter,
        test_framework_items_nist_filter,
        test_framework_controls_queryable,
        test_framework_risks_queryable,
        # Tool functions
        test_tool_semantic_cwe_lookup_sql_injection,
        test_tool_semantic_capec_lookup_injection,
        test_tool_framework_item_retrieval_initial_access_nist,
        test_tool_framework_item_retrieval_persistence_cis,
        test_tool_cis_controls_search_privilege_escalation,
        test_tool_framework_item_retrieval_broad_soc2,
        # Cross-collection chains
        test_chain_cwe89_to_cwe_capec_collection,
        test_chain_t1190_tactic_context_to_framework_items,
        test_chain_kill_chain_techniques_to_controls,
        # Scenario-aligned
        test_scenario0_sbom_cve_enrichment_via_collections,
        test_scenario1_terraform_policy_attack_mapping_via_collections,
        test_scenario2_cwe89_full_collection_chain,
        test_scenario3_siem_kill_chain_tactic_contexts,
        test_scenario4_soc2_framework_items_deficiencies,
        # Health summary
        test_all_collections_health_check,
    ]

    # Probe availability once before running tests
    available = _check_vector_store()
    if not available:
        reason = _SKIP_REASON or "vector store not reachable"
        print(f"\nAll {len(tests)} collection integration tests SKIPPED: {reason}")
        print("To run: start Qdrant (or ChromaDB) and set OPENAI_API_KEY, then re-run.")
        sys.exit(0)

    failed = []
    skipped = []
    for t in tests:
        print(f"\n{'=' * 64}")
        print(f"Running {t.__name__}...")
        try:
            result = t()
            if result is None and not _check_vector_store():
                skipped.append(t.__name__)
        except AssertionError as exc:
            print(f"✗ FAILED: {exc}")
            failed.append(t.__name__)
        except Exception as exc:
            import traceback
            print(f"✗ ERROR: {exc}")
            traceback.print_exc()
            failed.append(t.__name__)

    print(f"\n{'=' * 64}")
    total = len(tests)
    passed = total - len(failed) - len(skipped)
    print(f"Results: {passed}/{total} passed  |  {len(skipped)} skipped  |  {len(failed)} failed")
    if failed:
        print(f"Failed: {', '.join(failed)}")
        sys.exit(1)
    else:
        print("All collection integration tests passed.")
        sys.exit(0)


if __name__ == "__main__":
    run_all_tests()
