"""Schema SQLite, connessione, migrazioni e upsert dei record NVD.

SQL diretto con ``sqlite3`` e query sempre parametrizzate: nessun ORM.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from .config import (
    META_SCHEMA_VERSION,
    get_logger,
)
from .cpe import InvalidCPEError, normalize_name, parse_cpe23

__all__ = [
    "SCHEMA_VERSION",
    "DatabaseNotFoundError",
    "connect",
    "count_cves",
    "get_meta",
    "init_db",
    "parse_cve_item",
    "set_meta",
    "upsert_cves",
]

LOG = get_logger()

SCHEMA_VERSION = 1
BATCH_SIZE = 2000

_CWE_RE = re.compile(r"CWE-\d+")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cve (
  cve_id TEXT PRIMARY KEY,
  published TEXT, last_modified TEXT, vuln_status TEXT,
  description TEXT,
  cvss_version TEXT,
  cvss_score REAL, cvss_severity TEXT, cvss_vector TEXT,
  cwe TEXT,
  references_json TEXT,
  raw_json TEXT
);

CREATE TABLE IF NOT EXISTS cpe_match (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
  config_index INTEGER, node_index INTEGER,
  config_operator TEXT, node_operator TEXT, negate INTEGER,
  vulnerable INTEGER NOT NULL,
  criteria TEXT NOT NULL,
  part TEXT, vendor TEXT, product TEXT, version TEXT,
  update_field TEXT, edition TEXT, sw_edition TEXT, target_sw TEXT,
  target_hw TEXT, other TEXT,
  version_start_including TEXT, version_start_excluding TEXT,
  version_end_including TEXT, version_end_excluding TEXT
);

CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe_match(vendor, product);
CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe_match(product);
CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe_match(cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve(cvss_severity);

CREATE TABLE IF NOT EXISTS kev (
  cve_id TEXT PRIMARY KEY, date_added TEXT, ransomware TEXT, due_date TEXT
);
CREATE TABLE IF NOT EXISTS epss (
  cve_id TEXT PRIMARY KEY, score REAL, percentile REAL, updated TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

_CVE_COLUMNS = (
    "cve_id",
    "published",
    "last_modified",
    "vuln_status",
    "description",
    "cvss_version",
    "cvss_score",
    "cvss_severity",
    "cvss_vector",
    "cwe",
    "references_json",
    "raw_json",
)

_CPE_COLUMNS = (
    "cve_id",
    "config_index",
    "node_index",
    "config_operator",
    "node_operator",
    "negate",
    "vulnerable",
    "criteria",
    "part",
    "vendor",
    "product",
    "version",
    "update_field",
    "edition",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
)

_UPSERT_CVE_SQL = (
    f"INSERT INTO cve ({', '.join(_CVE_COLUMNS)}) "
    f"VALUES ({', '.join('?' * len(_CVE_COLUMNS))}) "
    "ON CONFLICT(cve_id) DO UPDATE SET "
    + ", ".join(f"{c}=excluded.{c}" for c in _CVE_COLUMNS if c != "cve_id")
)

_INSERT_CPE_SQL = (
    f"INSERT INTO cpe_match ({', '.join(_CPE_COLUMNS)}) "
    f"VALUES ({', '.join('?' * len(_CPE_COLUMNS))})"
)


class DatabaseNotFoundError(FileNotFoundError):
    """Il database locale non esiste ancora: serve una ``sync --full``."""


def connect(db_path: Path, create: bool = False) -> sqlite3.Connection:
    """Apre il database applicando i PRAGMA di lavoro.

    :param create: se False e il file non esiste solleva
        :class:`DatabaseNotFoundError` invece di crearne uno vuoto.
    """
    db_path = Path(db_path)
    if not create and not db_path.exists():
        raise DatabaseNotFoundError(
            f"database non trovato in {db_path}. "
            "Esegui prima 'nvdlocal sync --full' per popolarlo."
        )
    if create:
        db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Crea lo schema se assente e applica le migrazioni necessarie."""
    conn.executescript(SCHEMA_SQL)
    current = get_meta(conn, META_SCHEMA_VERSION)
    if current is None:
        set_meta(conn, META_SCHEMA_VERSION, str(SCHEMA_VERSION))
    elif int(current) < SCHEMA_VERSION:  # pragma: no cover - nessuna migrazione ancora
        _migrate(conn, int(current))
        set_meta(conn, META_SCHEMA_VERSION, str(SCHEMA_VERSION))
    conn.commit()


def _migrate(conn: sqlite3.Connection, from_version: int) -> None:  # pragma: no cover
    """Applica le migrazioni incrementali dello schema."""
    LOG.info("migrazione schema da v%s a v%s", from_version, SCHEMA_VERSION)
    # Lo schema e' alla v1: le migrazioni future si aggiungono qui.


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    """Legge un valore dalla tabella ``meta``."""
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    """Scrive un valore nella tabella ``meta`` (upsert)."""
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def count_cves(conn: sqlite3.Connection) -> int:
    """Numero di CVE presenti nel database locale."""
    return int(conn.execute("SELECT COUNT(*) AS n FROM cve").fetchone()["n"])


# --------------------------------------------------------------------------- #
# Parsing della risposta NVD 2.0
# --------------------------------------------------------------------------- #
#: Priorita' delle metriche CVSS: v4.0 > v3.1 > v3.0 > v2.
_METRIC_PRIORITY: tuple[tuple[str, str], ...] = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def _best_metric(metrics: dict[str, Any]) -> tuple[str | None, float | None, str | None, str | None]:
    """Sceglie la metrica CVSS migliore disponibile.

    Restituisce ``(version, score, severity, vector)``; preferisce le voci con
    ``type == "Primary"`` all'interno della stessa versione.
    """
    if not isinstance(metrics, dict):
        return (None, None, None, None)

    for key, default_version in _METRIC_PRIORITY:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        primary = next(
            (e for e in entries if isinstance(e, dict) and e.get("type") == "Primary"),
            None,
        )
        entry = primary if primary is not None else entries[0]
        if not isinstance(entry, dict):
            continue
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        # In CVSS v2 la severita' sta sulla voce, non dentro cvssData.
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return (
            str(data.get("version") or default_version),
            float(score) if isinstance(score, (int, float)) else None,
            str(severity).upper() if severity else None,
            data.get("vectorString"),
        )
    return (None, None, None, None)


def _english_description(descriptions: Any) -> str:
    """Estrae la descrizione inglese, con fallback sulla prima disponibile."""
    if not isinstance(descriptions, list):
        return ""
    for desc in descriptions:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            return str(desc.get("value") or "")
    for desc in descriptions:
        if isinstance(desc, dict) and desc.get("value"):
            return str(desc["value"])
    return ""


def _cwes(weaknesses: Any) -> str:
    """CSV dei CWE (solo identificatori ``CWE-xxx``, deduplicati)."""
    if not isinstance(weaknesses, list):
        return ""
    found: list[str] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description") or []:
            if not isinstance(desc, dict):
                continue
            for cwe in _CWE_RE.findall(str(desc.get("value") or "")):
                if cwe not in found:
                    found.append(cwe)
    return ",".join(found)


def _cpe_match_rows(cve_id: str, configurations: Any) -> list[tuple[Any, ...]]:
    """Appiattisce ``configurations`` in righe pronte per ``cpe_match``.

    ``configurations`` e' una lista di configurazioni, ciascuna con una lista di
    ``nodes``, ciascuno con una lista di ``cpeMatch``. I vincoli di versione
    stanno a livello di ``cpeMatch``, non dentro la stringa CPE. Le CVE senza
    ``configurations`` (rifiutate o in attesa di analisi) producono zero righe.
    """
    rows: list[tuple[Any, ...]] = []
    if not isinstance(configurations, list):
        return rows

    for config_index, config in enumerate(configurations):
        if not isinstance(config, dict):
            continue
        config_operator = config.get("operator")
        for node_index, node in enumerate(config.get("nodes") or []):
            if not isinstance(node, dict):
                continue
            node_operator = node.get("operator")
            negate = 1 if node.get("negate") else 0
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict):
                    continue
                criteria = match.get("criteria")
                if not criteria:
                    continue
                try:
                    cpe = parse_cpe23(str(criteria))
                except InvalidCPEError:
                    LOG.debug("CPE non parsabile in %s: %r", cve_id, criteria)
                    continue
                rows.append(
                    (
                        cve_id,
                        config_index,
                        node_index,
                        config_operator,
                        node_operator,
                        negate,
                        1 if match.get("vulnerable") else 0,
                        str(criteria),
                        cpe.part,
                        normalize_name(cpe.vendor) or cpe.vendor,
                        normalize_name(cpe.product) or cpe.product,
                        cpe.version,
                        cpe.update,
                        cpe.edition,
                        cpe.sw_edition,
                        cpe.target_sw,
                        cpe.target_hw,
                        cpe.other,
                        match.get("versionStartIncluding"),
                        match.get("versionStartExcluding"),
                        match.get("versionEndIncluding"),
                        match.get("versionEndExcluding"),
                    )
                )
    return rows


def parse_cve_item(item: dict[str, Any]) -> tuple[tuple[Any, ...], list[tuple[Any, ...]]]:
    """Trasforma un elemento ``vulnerabilities[]`` in righe ``cve`` + ``cpe_match``.

    :raises ValueError: se l'elemento non contiene un ``cve.id``.
    """
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict) or not cve.get("id"):
        raise ValueError("elemento NVD privo di cve.id")

    cve_id = str(cve["id"])
    version, score, severity, vector = _best_metric(cve.get("metrics") or {})
    cve_row = (
        cve_id,
        cve.get("published"),
        cve.get("lastModified"),
        cve.get("vulnStatus"),
        _english_description(cve.get("descriptions")),
        version,
        score,
        severity,
        vector,
        _cwes(cve.get("weaknesses")),
        json.dumps(cve.get("references") or [], ensure_ascii=False),
        json.dumps(item, ensure_ascii=False),
    )
    return cve_row, _cpe_match_rows(cve_id, cve.get("configurations"))


def _chunks(items: Sequence[Any], size: int) -> Iterator[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def upsert_cves(
    conn: sqlite3.Connection,
    items: Iterable[dict[str, Any]],
    batch_size: int = BATCH_SIZE,
) -> int:
    """Inserisce o aggiorna un blocco di CVE in transazioni da ``batch_size``.

    Per ogni CVE le righe ``cpe_match`` vengono cancellate e reinserite: le
    configurazioni cambiano nel tempo e l'operazione dev'essere idempotente.

    :return: numero di CVE effettivamente scritte.
    """
    parsed: list[tuple[tuple[Any, ...], list[tuple[Any, ...]]]] = []
    for item in items:
        try:
            parsed.append(parse_cve_item(item))
        except ValueError as exc:
            LOG.warning("elemento NVD scartato: %s", exc)

    written = 0
    for batch in _chunks(parsed, batch_size):
        cve_rows = [row for row, _ in batch]
        cve_ids = [(row[0],) for row in cve_rows]
        cpe_rows = [r for _, matches in batch for r in matches]
        try:
            with conn:  # transazione per blocco
                conn.executemany(_UPSERT_CVE_SQL, cve_rows)
                conn.executemany("DELETE FROM cpe_match WHERE cve_id = ?", cve_ids)
                if cpe_rows:
                    conn.executemany(_INSERT_CPE_SQL, cpe_rows)
        except sqlite3.Error as exc:  # pragma: no cover - errori di I/O
            LOG.error("errore di scrittura sul database: %s", exc)
            raise
        written += len(cve_rows)
    return written


def database_size(db_path: Path) -> int:
    """Dimensione totale su disco del database (inclusi WAL e shared memory)."""
    total = 0
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(db_path) + suffix)
        if candidate.exists():
            total += candidate.stat().st_size
    return total
