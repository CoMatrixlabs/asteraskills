"""
CISA Known Exploited Vulnerabilities (KEV) catalog client.

The KEV catalog is a deterministic, binary check — a CVE is either in the catalog
or it is not. This client fetches and caches the official CISA JSON feed, provides
fast CVE → KevEntry lookups, and supports continuous inventory monitoring (watch mode).

Optional **Qdrant** / **Postgres** sources (``asteraskills`` settings / ``.env``) after ingesting with
``python -m asteraskills.ingestion.cisa_kev_qdrant_ingest``. Lookups try Postgres first (if
``KEV_USE_POSTGRES``), then Qdrant (if ``KEV_USE_QDRANT``, default on). When Qdrant responds
(collection exists, query succeeds), membership is authoritative — the CISA feed is not fetched.
If Qdrant is unavailable or the collection is missing, falls back to local JSON cache / CISA URL.

Catalog source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from risk_scanner.core.models import KevEntry, Severity

log = logging.getLogger(__name__)

_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_CACHE_FILENAME = "kev_catalog.json"
_DEFAULT_CACHE_DIR = Path.home() / ".risk-scanner" / "cache"

# Known ransomware group mentions in CISA notes (case-insensitive substring match)
_RANSOMWARE_GROUP_PATTERNS: List[str] = [
    "LockBit", "Cl0p", "ALPHV", "BlackCat", "REvil", "Sodinokibi",
    "Conti", "Hive", "BlackBasta", "Royal", "Play", "Cuba",
    "AvosLocker", "Ragnar Locker", "Vice Society", "BianLian",
]

# Minimal static fallback catalog for offline / test use.
# Contains a representative sample of well-known KEV entries.
_STATIC_FALLBACK: Dict[str, dict] = {
    "CVE-2021-44228": {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-10",
        "shortDescription": (
            "Apache Log4j2 contains a remote code execution vulnerability via JNDI. "
            "An unauthenticated attacker can exploit this vulnerability."
        ),
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Ransomware groups including Conti, LockBit have actively exploited this CVE.",
    },
    "CVE-2021-45046": {
        "cveID": "CVE-2021-45046",
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 Deserialization of Untrusted Data Vulnerability",
        "dateAdded": "2021-12-14",
        "shortDescription": "Apache Log4j2 additional Log4Shell variant.",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2021-12-28",
        "knownRansomwareCampaignUse": "Known",
        "notes": "",
    },
    "CVE-2023-44487": {
        "cveID": "CVE-2023-44487",
        "vendorProject": "Multiple",
        "product": "HTTP/2",
        "vulnerabilityName": "HTTP/2 Rapid Reset Attack Vulnerability",
        "dateAdded": "2023-10-10",
        "shortDescription": "HTTP/2 Rapid Reset vulnerability allowing DoS via stream cancellation.",
        "requiredAction": "Apply mitigations per vendor instructions or discontinue product use.",
        "dueDate": "2023-10-31",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
    },
    "CVE-2024-3400": {
        "cveID": "CVE-2024-3400",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
        "dateAdded": "2024-04-12",
        "shortDescription": (
            "Palo Alto Networks PAN-OS GlobalProtect gateway command injection vulnerability "
            "allows unauthenticated remote code execution."
        ),
        "requiredAction": "Apply updates per vendor instructions immediately.",
        "dueDate": "2024-04-19",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Exploited in the wild by threat actors. UTA0218 threat group confirmed.",
    },
    "CVE-2022-47966": {
        "cveID": "CVE-2022-47966",
        "vendorProject": "Zoho",
        "product": "ManageEngine",
        "vulnerabilityName": "Zoho ManageEngine Remote Code Execution Vulnerability",
        "dateAdded": "2023-01-23",
        "shortDescription": "Zoho ManageEngine unauthenticated RCE via Apache Santuario.",
        "requiredAction": "Apply vendor updates.",
        "dueDate": "2023-02-13",
        "knownRansomwareCampaignUse": "Known",
        "notes": "PoC publicly available. Cl0p ransomware group has exploited this vulnerability.",
    },
    "CVE-2023-34362": {
        "cveID": "CVE-2023-34362",
        "vendorProject": "Progress",
        "product": "MOVEit Transfer",
        "vulnerabilityName": "Progress MOVEit Transfer SQL Injection Vulnerability",
        "dateAdded": "2023-06-02",
        "shortDescription": "SQL injection vulnerability in MOVEit Transfer allowing unauthorized access.",
        "requiredAction": "Apply updates per vendor instructions immediately.",
        "dueDate": "2023-06-23",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Cl0p ransomware group has actively exploited this vulnerability at scale.",
    },
}


def _qdrant_client_from_settings(s: object):
    """Build a sync ``QdrantClient`` from asteraskills settings (host/port or ``QDRANT_URL``)."""
    from qdrant_client import QdrantClient

    url = getattr(s, "QDRANT_URL", None)
    key = getattr(s, "QDRANT_API_KEY", None) or None
    if url:
        return QdrantClient(url=str(url), api_key=key)
    host = getattr(s, "QDRANT_HOST", None) or "localhost"
    port = int(getattr(s, "QDRANT_PORT", 6333) or 6333)
    return QdrantClient(host=host, port=port, api_key=key)


class KevClient:
    """CISA KEV catalog client with caching and optional offline/test mode.

    In normal use, the catalog is fetched from CISA on first access and cached
    locally for ``cache_ttl_hours``. Subsequent lookups use the cache.

    For offline use or testing, pass ``_test_catalog`` to bypass HTTP and disk.

    Args:
        cache_dir: Directory for the local cache file. Defaults to ~/.risk-scanner/cache.
        cache_ttl_hours: How long to use the cached catalog before re-fetching.
        offline: If True, never fetch from CISA — use cache or static fallback only.
        use_qdrant: If True, resolve CVEs from Qdrant collection ``CISA_KEV_COLLECTION``.
            If ``None``, reads ``KEV_USE_QDRANT`` from asteraskills settings (default True when importable).
        use_postgres: If True, resolve CVEs from Postgres table ``cisa_kev`` before Qdrant/file.
            If ``None``, reads ``KEV_USE_POSTGRES`` from asteraskills settings when importable.
        _test_catalog: Optional dict {cve_id: raw_entry} for testing without I/O.
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        cache_ttl_hours: int = 6,
        offline: bool = False,
        use_qdrant: Optional[bool] = None,
        use_postgres: Optional[bool] = None,
        _test_catalog: Optional[Dict[str, dict]] = None,
    ) -> None:
        self._cache_dir = Path(cache_dir) if cache_dir else _DEFAULT_CACHE_DIR
        self._cache_ttl = timedelta(hours=cache_ttl_hours)
        self._offline = offline
        self._test_catalog = _test_catalog  # overrides everything when set
        self._pg_engine: Any = None  # lazy SQLAlchemy engine
        if _test_catalog is not None:
            self._use_qdrant = False
            self._use_postgres = False
        else:
            if use_qdrant is not None:
                self._use_qdrant = bool(use_qdrant)
            else:
                self._use_qdrant = False
                try:
                    from asteraskills.config.settings import get_settings

                    self._use_qdrant = bool(get_settings().KEV_USE_QDRANT)
                except Exception:  # noqa: BLE001
                    pass
            if use_postgres is not None:
                self._use_postgres = bool(use_postgres)
            else:
                self._use_postgres = False
                try:
                    from asteraskills.config.settings import get_settings

                    self._use_postgres = bool(get_settings().KEV_USE_POSTGRES)
                except Exception:  # noqa: BLE001
                    pass
        self._index: Optional[Dict[str, dict]] = None  # CVE-ID (upper) → raw entry
        self._index_loaded_at: Optional[datetime] = None
        self._watch_thread: Optional[threading.Thread] = None
        self._watch_stop = threading.Event()

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def lookup(self, cve_id: str) -> KevEntry:
        """Look up a CVE in the KEV catalog.

        Returns a ``KevEntry`` with ``in_kev=False`` if the CVE is not in the catalog.
        Never raises; network errors fall back to the static catalog.
        """
        if self._use_postgres:
            raw_p = self._postgres_raw_for_cve(cve_id)
            if raw_p is not None:
                return _parse_raw_entry(raw_p)
        if self._use_qdrant:
            raw_q, need_fallback = self._qdrant_resolve(cve_id)
            if raw_q is not None:
                return _parse_raw_entry(raw_q)
            if not need_fallback:
                return KevEntry(in_kev=False)
        index = self._get_index()
        raw = index.get(cve_id.upper())
        if raw is None:
            return KevEntry(in_kev=False)
        return _parse_raw_entry(raw)

    def is_in_kev(self, cve_id: str) -> bool:
        """Fast boolean check — no KevEntry parsing overhead."""
        if self._use_postgres and self._postgres_raw_for_cve(cve_id) is not None:
            return True
        if self._use_qdrant:
            raw_q, need_fallback = self._qdrant_resolve(cve_id)
            if raw_q is not None:
                return True
            if not need_fallback:
                return False
        return cve_id.upper() in self._get_index()

    def kev_count(self) -> int:
        """Return the number of CVEs currently in the KEV catalog."""
        if self._use_postgres:
            n = self._postgres_row_count()
            if n is not None:
                return n
        if self._use_qdrant:
            n = self._qdrant_point_count()
            if n is not None:
                return n
        return len(self._get_index())

    def _postgres_engine(self) -> Any:
        if self._pg_engine is not None:
            return self._pg_engine
        try:
            from asteraskills.config.settings import get_settings
            from asteraskills.storage.cisa_kev_postgres import (
                postgres_configured,
                postgres_engine_from_settings,
            )

            s = get_settings()
            if not postgres_configured(s):
                return None
            self._pg_engine = postgres_engine_from_settings(s)
            return self._pg_engine
        except Exception as exc:  # noqa: BLE001
            log.debug("KEV Postgres engine init failed: %s", exc)
            return None

    def _postgres_raw_for_cve(self, cve_id: str) -> Optional[dict]:
        try:
            from asteraskills.storage.cisa_kev_postgres import fetch_raw_for_cve

            eng = self._postgres_engine()
            if eng is None:
                return None
            return fetch_raw_for_cve(eng, cve_id)
        except Exception as exc:  # noqa: BLE001
            log.debug("KEV Postgres lookup failed for %s: %s", cve_id, exc)
            return None

    def _postgres_row_count(self) -> Optional[int]:
        try:
            from asteraskills.storage.cisa_kev_postgres import count_rows

            eng = self._postgres_engine()
            if eng is None:
                return None
            return count_rows(eng)
        except Exception as exc:  # noqa: BLE001
            log.debug("KEV Postgres count failed: %s", exc)
            return None

    def _qdrant_resolve(self, cve_id: str) -> tuple[Optional[dict], bool]:
        """Look up a CVE in the KEV Qdrant collection.

        Returns:
            (raw_cisa_entry, need_fallback): ``raw_cisa_entry`` is the CISA vulnerability dict if
            found. If ``raw_cisa_entry`` is ``None`` and ``need_fallback`` is ``False``, the CVE is
            not in KEV per Qdrant (no HTTP/catalog fallback). If ``need_fallback`` is ``True``,
            use the local cache / CISA URL (Qdrant missing, error, or malformed payload).
        """
        try:
            from qdrant_client.models import FieldCondition, Filter, MatchValue

            from asteraskills.config.settings import get_settings

            s = get_settings()
            coll = getattr(s, "CISA_KEV_COLLECTION", "cisa_kev")
            client = _qdrant_client_from_settings(s)
            if not client.collection_exists(collection_name=coll):
                return None, True
            pts, _ = client.scroll(
                collection_name=coll,
                scroll_filter=Filter(
                    must=[
                        FieldCondition(
                            key="cve_id",
                            match=MatchValue(value=cve_id.strip().upper()),
                        )
                    ]
                ),
                limit=1,
                with_payload=True,
                with_vectors=False,
            )
            if not pts:
                return None, False
            payload = pts[0].payload or {}
            raw = payload.get("raw")
            if isinstance(raw, dict):
                return raw, False
            return None, True
        except Exception as exc:  # noqa: BLE001
            log.debug("KEV Qdrant lookup failed for %s: %s", cve_id, exc)
            return None, True

    def _qdrant_point_count(self) -> Optional[int]:
        try:
            from asteraskills.config.settings import get_settings

            s = get_settings()
            coll = getattr(s, "CISA_KEV_COLLECTION", "cisa_kev")
            client = _qdrant_client_from_settings(s)
            if not client.collection_exists(collection_name=coll):
                return None
            out = client.count(collection_name=coll, exact=True)
            return int(out.count)
        except Exception as exc:  # noqa: BLE001
            log.debug("KEV Qdrant count failed: %s", exc)
            return None

    def watch(
        self,
        component_inventory: Dict[str, str],  # {cve_id: component_name}
        callback: Callable[[str, KevEntry], None],
        poll_interval_seconds: int = 3600 * 6,
    ) -> None:
        """Start background polling. Calls callback(cve_id, kev_entry) on new KEV matches.

        Runs in a daemon thread. Call ``stop_watch()`` to terminate.

        Args:
            component_inventory: Dict of {cve_id: component_name} to monitor.
            callback: Called with (cve_id, KevEntry) whenever a monitored CVE appears in KEV.
            poll_interval_seconds: How often to refresh the catalog (default: 6 hours).
        """
        if self._watch_thread and self._watch_thread.is_alive():
            log.warning("KEV watch already running — stop with stop_watch() first")
            return

        self._watch_stop.clear()
        known_kev_ids: set = {
            cve_id for cve_id in component_inventory
            if self.is_in_kev(cve_id)
        }

        def _poll_loop() -> None:
            while not self._watch_stop.wait(timeout=poll_interval_seconds):
                self._refresh_index()
                new_matches = []
                for cve_id in component_inventory:
                    if cve_id.upper() not in known_kev_ids and self.is_in_kev(cve_id):
                        known_kev_ids.add(cve_id.upper())
                        new_matches.append(cve_id)
                for cve_id in new_matches:
                    try:
                        callback(cve_id, self.lookup(cve_id))
                    except Exception as exc:
                        log.warning("KEV watch callback error for %s: %s", cve_id, exc)

        self._watch_thread = threading.Thread(
            target=_poll_loop, name="kev-watch", daemon=True
        )
        self._watch_thread.start()
        log.info(
            "KEV watch started: monitoring %d CVEs every %ds",
            len(component_inventory), poll_interval_seconds,
        )

    def stop_watch(self) -> None:
        """Stop the background watch thread."""
        self._watch_stop.set()
        if self._watch_thread:
            self._watch_thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------

    def _get_index(self) -> Dict[str, dict]:
        """Return the CVE index, loading/refreshing as needed."""
        if self._test_catalog is not None:
            return {k.upper(): v for k, v in self._test_catalog.items()}

        if self._index is not None and self._index_loaded_at is not None:
            age = datetime.utcnow() - self._index_loaded_at
            if age < self._cache_ttl:
                return self._index

        self._refresh_index()
        return self._index or {}

    def _refresh_index(self) -> None:
        """Load catalog from cache file, or fetch from CISA if stale/missing."""
        # 1. Try disk cache
        if self._load_from_cache():
            return
        # 2. Try live fetch
        if not self._offline:
            if self._fetch_from_cisa():
                return
        # 3. Static fallback
        log.info("KEV: using static fallback catalog (%d entries)", len(_STATIC_FALLBACK))
        self._index = {k.upper(): v for k, v in _STATIC_FALLBACK.items()}
        self._index_loaded_at = datetime.utcnow()

    def _load_from_cache(self) -> bool:
        cache_file = self._cache_dir / _CACHE_FILENAME
        if not cache_file.is_file():
            return False
        try:
            mtime = datetime.utcfromtimestamp(cache_file.stat().st_mtime)
            if datetime.utcnow() - mtime > self._cache_ttl:
                return False  # cache is stale
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            self._index = {e["cveID"].upper(): e for e in data.get("vulnerabilities", [])}
            self._index_loaded_at = mtime
            log.debug("KEV: loaded %d entries from cache", len(self._index))
            return True
        except Exception as exc:
            log.debug("KEV cache load failed: %s", exc)
            return False

    def _fetch_from_cisa(self) -> bool:
        try:
            import urllib.request
            log.info("KEV: fetching catalog from CISA...")
            with urllib.request.urlopen(_CATALOG_URL, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            self._index = {e["cveID"].upper(): e for e in data.get("vulnerabilities", [])}
            self._index_loaded_at = datetime.utcnow()
            log.info("KEV: fetched %d entries from CISA", len(self._index))
            # Persist to cache
            try:
                self._cache_dir.mkdir(parents=True, exist_ok=True)
                (self._cache_dir / _CACHE_FILENAME).write_text(
                    json.dumps(data, indent=2), encoding="utf-8"
                )
            except Exception as exc:
                log.debug("KEV cache write failed: %s", exc)
            return True
        except Exception as exc:
            log.warning("KEV: CISA fetch failed (%s) — falling back", exc)
            return False


# ------------------------------------------------------------------
# Parsing helpers
# ------------------------------------------------------------------

def _parse_raw_entry(raw: dict) -> KevEntry:
    """Convert a raw CISA catalog entry dict to a KevEntry model."""
    cve_id = raw.get("cveID", "")
    date_added = _parse_date(raw.get("dateAdded"))
    due_date = _parse_date(raw.get("dueDate"))
    days_until_due: Optional[int] = None
    if due_date:
        days_until_due = (due_date - date.today()).days

    ransomware_use = (raw.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
    ransomware_group = _extract_ransomware_group(raw.get("notes") or "")

    return KevEntry(
        in_kev=True,
        kev_date_added=date_added,
        kev_due_date=due_date,
        days_until_due=days_until_due,
        ransomware_campaign_use=ransomware_use,
        ransomware_group=ransomware_group,
        required_action=raw.get("requiredAction"),
        kev_notes=raw.get("notes") or None,
        severity_was_upgraded=False,   # set by EnrichmentAnalyzer after applying override
        pre_kev_severity=None,
    )


def _parse_date(s: Optional[str]) -> Optional[date]:
    if not s:
        return None
    try:
        return date.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _extract_ransomware_group(notes: str) -> Optional[str]:
    """Try to identify a named ransomware group from CISA notes text."""
    for group in _RANSOMWARE_GROUP_PATTERNS:
        if group.lower() in notes.lower():
            return group
    return None
