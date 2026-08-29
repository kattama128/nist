"""Download dei dati dall'API NVD 2.0: sync completa (con resume) e incrementale.

Include rate limiting conservativo, retry con backoff esponenziale sugli
errori tipici dell'API NVD (403/429/503 e timeout) e checkpoint su ``meta``
dopo ogni pagina, cosi' una sync interrotta riparte da dove si era fermata.
"""

from __future__ import annotations

import random
import sqlite3
import time
from contextlib import AbstractContextManager
from datetime import datetime, timedelta, timezone
from types import TracebackType
from typing import Any, Iterator

import httpx

from .config import (
    BACKOFF_MAX,
    BACKOFF_MIN,
    DELAY_WITH_KEY,
    DELAY_WITHOUT_KEY,
    HTTP_TIMEOUT,
    MAX_RESULTS_PER_PAGE,
    MAX_RETRIES,
    MAX_WINDOW_DAYS,
    META_FULL_SYNC_DONE,
    META_FULL_SYNC_INDEX,
    META_FULL_SYNC_TOTAL,
    META_LAST_SYNC,
    NVD_CVE_API,
    NVD_DATE_FMT,
    RETRY_STATUS,
    get_logger,
)
from .db import get_meta, set_meta, upsert_cves

__all__ = [
    "NVDClient",
    "NVDError",
    "NetworkError",
    "SyncStats",
    "sync_full",
    "sync_incremental",
]

LOG = get_logger()


class NVDError(RuntimeError):
    """Errore applicativo durante il dialogo con l'API NVD."""


class NetworkError(NVDError):
    """La rete non e' raggiungibile o l'API non risponde dopo tutti i retry."""


class SyncStats:
    """Contatori di una sessione di sincronizzazione."""

    def __init__(self) -> None:
        self.pages = 0
        self.cves = 0
        self.total_results = 0
        self.completed = False

    def __repr__(self) -> str:  # pragma: no cover - diagnostica
        return (
            f"SyncStats(pages={self.pages}, cves={self.cves}, "
            f"total={self.total_results}, completed={self.completed})"
        )


class NVDClient(AbstractContextManager["NVDClient"]):
    """Client HTTP per l'API NVD 2.0 con rate limiting e retry.

    Il rate limit reale e' 5 richieste / 30s senza API key e 50 / 30s con key;
    qui si usa una pausa fissa conservativa fra richieste consecutive.
    """

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = HTTP_TIMEOUT,
        delay: float | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.api_key = api_key
        self.delay = delay if delay is not None else (
            DELAY_WITH_KEY if api_key else DELAY_WITHOUT_KEY
        )
        headers = {"User-Agent": "nvdlocal/1.0 (+vulnerability-assessment)"}
        if api_key:
            headers["apiKey"] = api_key
        self._client = client or httpx.Client(timeout=timeout, headers=headers)
        self._owns_client = client is None
        self._last_request: float = 0.0

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Chiude il client HTTP sottostante se e' stato creato qui."""
        if self._owns_client:
            self._client.close()

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if self._last_request and elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request = time.monotonic()

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Esegue una GET con rate limiting e retry, restituendo il JSON.

        :raises NetworkError: se dopo :data:`MAX_RETRIES` tentativi non si
            ottiene una risposta utilizzabile.
        """
        last_error: str = "errore sconosciuto"
        for attempt in range(MAX_RETRIES):
            self._throttle()
            try:
                response = self._client.get(url, params=params)
            except httpx.TimeoutException as exc:
                last_error = f"timeout: {exc}"
            except httpx.TransportError as exc:
                last_error = f"rete non raggiungibile: {exc}"
            else:
                if response.status_code == 200:
                    try:
                        return response.json()
                    except ValueError as exc:
                        last_error = f"risposta non JSON: {exc}"
                elif response.status_code in RETRY_STATUS:
                    last_error = f"HTTP {response.status_code}"
                    retry_after = _retry_after(response)
                    if retry_after is not None:
                        LOG.warning(
                            "NVD ha risposto %s, attendo %.0fs (Retry-After)",
                            response.status_code,
                            retry_after,
                        )
                        time.sleep(retry_after)
                        continue
                else:
                    raise NVDError(
                        f"risposta inattesa dall'API NVD: HTTP {response.status_code} "
                        f"{response.text[:200]}"
                    )

            wait = _backoff(attempt)
            LOG.warning(
                "tentativo %s/%s fallito (%s), nuovo tentativo fra %.0fs",
                attempt + 1,
                MAX_RETRIES,
                last_error,
                wait,
            )
            time.sleep(wait)

        raise NetworkError(
            f"API NVD non raggiungibile dopo {MAX_RETRIES} tentativi ({last_error}). "
            "Verifica la connettivita' di rete o riprova piu' tardi."
        )


def _retry_after(response: httpx.Response) -> float | None:
    """Legge l'header ``Retry-After`` se presente e sensato."""
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return min(max(float(raw), BACKOFF_MIN), BACKOFF_MAX)
    except ValueError:
        return None


def _backoff(attempt: int) -> float:
    """Backoff esponenziale da 10s a 120s, con jitter."""
    base = min(BACKOFF_MIN * (2**attempt), BACKOFF_MAX)
    return base + random.uniform(0, min(base * 0.1, 5.0))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(moment: datetime) -> str:
    """Formatta una data nel formato ISO-8601 accettato da NVD."""
    return moment.astimezone(timezone.utc).strftime(NVD_DATE_FMT)


def _parse_iso(value: str) -> datetime:
    """Interpreta una data ISO-8601 NVD (con o senza timezone) come UTC."""
    text = value.strip().replace("Z", "+00:00")
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def windows(start: datetime, end: datetime, max_days: int = MAX_WINDOW_DAYS) -> Iterator[tuple[datetime, datetime]]:
    """Spezza l'intervallo in finestre non superiori a ``max_days`` giorni.

    L'API NVD rifiuta intervalli ``lastModStartDate``/``lastModEndDate``
    superiori a 120 giorni.
    """
    if end <= start:
        return
    span = timedelta(days=max_days)
    cursor = start
    while cursor < end:
        stop = min(cursor + span, end)
        yield cursor, stop
        cursor = stop


# --------------------------------------------------------------------------- #
# Sync completa
# --------------------------------------------------------------------------- #
def sync_full(
    conn: sqlite3.Connection,
    client: NVDClient,
    resume: bool = False,
    max_pages: int | None = None,
    results_per_page: int = MAX_RESULTS_PER_PAGE,
    progress: Any | None = None,
) -> SyncStats:
    """Scarica l'intero catalogo CVE, pagina per pagina, con checkpoint.

    :param resume: riparte dallo ``startIndex`` salvato in ``meta``.
    :param max_pages: limita il numero di pagine scaricate (utile per test reali).
    :param progress: istanza ``rich.progress.Progress`` opzionale.
    """
    stats = SyncStats()
    start_index = 0
    if resume:
        saved = get_meta(conn, META_FULL_SYNC_INDEX)
        start_index = int(saved) if saved and saved.isdigit() else 0
        if start_index:
            LOG.info("resume della sync completa da startIndex=%s", start_index)

    task_id = None
    started_at = _now()

    while True:
        if max_pages is not None and stats.pages >= max_pages:
            LOG.info("raggiunto il limite di %s pagine", max_pages)
            break

        payload = client.get_json(
            NVD_CVE_API,
            {"resultsPerPage": results_per_page, "startIndex": start_index},
        )
        total = int(payload.get("totalResults") or 0)
        items = payload.get("vulnerabilities") or []
        stats.total_results = total

        if stats.pages == 0:
            set_meta(conn, META_FULL_SYNC_TOTAL, str(total))
            conn.commit()
            LOG.info("catalogo NVD: %s CVE totali", f"{total:,}")
            if progress is not None:
                task_id = progress.add_task(
                    "[cyan]sync completa", total=total, completed=start_index
                )

        written = upsert_cves(conn, items)
        stats.cves += written
        stats.pages += 1

        page_size = int(payload.get("resultsPerPage") or len(items))
        start_index += page_size or len(items)
        set_meta(conn, META_FULL_SYNC_INDEX, str(start_index))
        conn.commit()

        if progress is not None and task_id is not None:
            progress.update(task_id, completed=min(start_index, total))

        LOG.debug("pagina %s: %s CVE scritte (startIndex ora %s)", stats.pages, written, start_index)

        if not items or start_index >= total:
            stats.completed = True
            break

    if stats.completed:
        set_meta(conn, META_FULL_SYNC_INDEX, "0")
        set_meta(conn, META_FULL_SYNC_DONE, _fmt(_now()))
        set_meta(conn, META_LAST_SYNC, _fmt(started_at))
        conn.commit()
        LOG.info("sync completa terminata: %s CVE", f"{stats.cves:,}")
    else:
        LOG.info(
            "sync interrotta a startIndex=%s: riprendi con 'sync --full --resume'",
            start_index,
        )
    return stats


# --------------------------------------------------------------------------- #
# Sync incrementale
# --------------------------------------------------------------------------- #
def _incremental_start(conn: sqlite3.Connection) -> datetime:
    """Determina il punto di partenza della sync incrementale.

    Usa ``meta.last_sync`` meno un'ora di margine; in mancanza ricade sul
    massimo ``last_modified`` presente nel database.
    """
    saved = get_meta(conn, META_LAST_SYNC)
    if not saved:
        row = conn.execute("SELECT MAX(last_modified) AS m FROM cve").fetchone()
        saved = row["m"] if row and row["m"] else None
    if not saved:
        raise NVDError(
            "nessuna sincronizzazione precedente: esegui prima 'nvdlocal sync --full'."
        )
    return _parse_iso(saved) - timedelta(hours=1)


def sync_incremental(
    conn: sqlite3.Connection,
    client: NVDClient,
    results_per_page: int = MAX_RESULTS_PER_PAGE,
    progress: Any | None = None,
) -> SyncStats:
    """Scarica solo le CVE modificate dall'ultima sincronizzazione.

    Se l'ultima sync e' piu' vecchia di 120 giorni la richiesta viene spezzata
    in piu' finestre, come richiesto dall'API.
    """
    stats = SyncStats()
    start = _incremental_start(conn)
    end = _now()
    started_at = end

    window_list = list(windows(start, end))
    if not window_list:
        LOG.info("nessuna finestra da sincronizzare: database gia' aggiornato")
        stats.completed = True
        return stats

    LOG.info(
        "sync incrementale da %s a %s (%s finestre)",
        _fmt(start),
        _fmt(end),
        len(window_list),
    )

    task_id = None
    if progress is not None:
        task_id = progress.add_task("[cyan]sync incrementale", total=None)

    for window_start, window_end in window_list:
        start_index = 0
        while True:
            payload = client.get_json(
                NVD_CVE_API,
                {
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                    "lastModStartDate": _fmt(window_start),
                    "lastModEndDate": _fmt(window_end),
                },
            )
            total = int(payload.get("totalResults") or 0)
            items = payload.get("vulnerabilities") or []
            stats.total_results += total if start_index == 0 else 0

            if progress is not None and task_id is not None and start_index == 0:
                progress.update(task_id, total=stats.total_results)

            stats.cves += upsert_cves(conn, items)
            stats.pages += 1

            page_size = int(payload.get("resultsPerPage") or len(items))
            start_index += page_size or len(items)

            if progress is not None and task_id is not None:
                progress.update(task_id, completed=stats.cves)

            if not items or start_index >= total:
                break

    set_meta(conn, META_LAST_SYNC, _fmt(started_at))
    conn.commit()
    stats.completed = True
    LOG.info("sync incrementale terminata: %s CVE aggiornate", f"{stats.cves:,}")
    return stats
