"""Arricchimento dei dati: CISA KEV (sfruttamento noto) ed EPSS (probabilita').

Entrambe le sorgenti sono indipendenti dall'API NVD e non hanno rate limit
significativi: si scaricano interamente a ogni aggiornamento.
"""

from __future__ import annotations

import csv
import gzip
import io
import sqlite3
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import (
    EPSS_URL,
    HTTP_TIMEOUT,
    KEV_URL,
    META_EPSS_SYNC,
    META_KEV_SYNC,
    get_logger,
)
from .db import set_meta

__all__ = ["EnrichError", "sync_enrichment", "sync_epss", "sync_kev"]

LOG = get_logger()


class EnrichError(RuntimeError):
    """Errore durante il download o il parsing delle sorgenti di arricchimento."""


def _fetch(url: str, timeout: float = HTTP_TIMEOUT) -> httpx.Response:
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "nvdlocal/1.0"},
        ) as client:
            response = client.get(url)
    except httpx.TimeoutException as exc:
        raise EnrichError(f"timeout scaricando {url}: {exc}") from exc
    except httpx.TransportError as exc:
        raise EnrichError(
            f"rete non raggiungibile scaricando {url}: {exc}"
        ) from exc
    if response.status_code != 200:
        raise EnrichError(f"HTTP {response.status_code} scaricando {url}")
    return response


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sync_kev(conn: sqlite3.Connection) -> int:
    """Scarica il catalogo CISA KEV e popola la tabella ``kev``.

    :return: numero di CVE nel catalogo.
    """
    LOG.info("scarico il catalogo CISA KEV")
    try:
        payload: dict[str, Any] = _fetch(KEV_URL).json()
    except ValueError as exc:
        raise EnrichError(f"catalogo KEV non in formato JSON: {exc}") from exc

    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        raise EnrichError("catalogo KEV senza campo 'vulnerabilities'")

    rows = [
        (
            str(entry.get("cveID")).upper(),
            entry.get("dateAdded"),
            entry.get("knownRansomwareCampaignUse"),
            entry.get("dueDate"),
        )
        for entry in entries
        if isinstance(entry, dict) and entry.get("cveID")
    ]

    with conn:
        conn.execute("DELETE FROM kev")
        conn.executemany(
            "INSERT INTO kev (cve_id, date_added, ransomware, due_date) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(cve_id) DO UPDATE SET "
            "date_added=excluded.date_added, ransomware=excluded.ransomware, "
            "due_date=excluded.due_date",
            rows,
        )
        set_meta(conn, META_KEV_SYNC, _timestamp())
    LOG.info("KEV aggiornato: %s CVE con sfruttamento noto", f"{len(rows):,}")
    return len(rows)


def _decompress(payload: bytes) -> str:
    """Decomprime il CSV EPSS gestendo il caso in cui httpx l'abbia gia' fatto."""
    if payload[:2] == b"\x1f\x8b":
        payload = gzip.decompress(payload)
    return payload.decode("utf-8", errors="replace")


def sync_epss(conn: sqlite3.Connection) -> int:
    """Scarica gli score EPSS giornalieri e popola la tabella ``epss``.

    Il CSV compresso inizia con righe di commento (``#model_version:...``) che
    vengono saltate prima dell'header.

    :return: numero di righe importate.
    """
    LOG.info("scarico gli score EPSS")
    response = _fetch(EPSS_URL)
    try:
        text = _decompress(response.content)
    except (OSError, gzip.BadGzipFile) as exc:
        raise EnrichError(f"CSV EPSS non decomprimibile: {exc}") from exc

    stream = io.StringIO(text)
    model_date = ""
    header: list[str] | None = None
    while True:
        line = stream.readline()
        if not line:
            break
        stripped = line.strip()
        if stripped.startswith("#"):
            if "score_date:" in stripped:
                model_date = stripped.split("score_date:", 1)[1].split(",")[0]
            continue
        if stripped:
            header = next(csv.reader([stripped]))
            break

    if not header or "cve" not in [h.strip().lower() for h in header]:
        raise EnrichError("CSV EPSS senza header 'cve,epss,percentile'")

    columns = [h.strip().lower() for h in header]
    idx_cve = columns.index("cve")
    idx_score = columns.index("epss") if "epss" in columns else 1
    idx_pct = columns.index("percentile") if "percentile" in columns else 2
    updated = model_date or _timestamp()

    rows: list[tuple[Any, ...]] = []
    for record in csv.reader(stream):
        if not record or record[0].startswith("#"):
            continue
        try:
            rows.append(
                (
                    record[idx_cve].strip().upper(),
                    float(record[idx_score]),
                    float(record[idx_pct]),
                    updated,
                )
            )
        except (IndexError, ValueError):
            LOG.debug("riga EPSS ignorata: %r", record)

    with conn:
        conn.executemany(
            "INSERT INTO epss (cve_id, score, percentile, updated) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(cve_id) DO UPDATE SET "
            "score=excluded.score, percentile=excluded.percentile, "
            "updated=excluded.updated",
            rows,
        )
        set_meta(conn, META_EPSS_SYNC, _timestamp())
    LOG.info("EPSS aggiornato: %s score (score_date %s)", f"{len(rows):,}", updated)
    return len(rows)


def sync_enrichment(conn: sqlite3.Connection) -> tuple[int, int]:
    """Aggiorna sia KEV sia EPSS.

    Un fallimento su una delle due sorgenti non impedisce l'altra: l'errore
    viene loggato e il conteggio corrispondente resta a zero.

    :return: ``(numero_kev, numero_epss)``.
    """
    kev_count = 0
    epss_count = 0
    try:
        kev_count = sync_kev(conn)
    except EnrichError as exc:
        LOG.error("aggiornamento KEV fallito: %s", exc)
    try:
        epss_count = sync_epss(conn)
    except EnrichError as exc:
        LOG.error("aggiornamento EPSS fallito: %s", exc)
    return kev_count, epss_count
