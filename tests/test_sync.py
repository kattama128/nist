"""Test della sincronizzazione: paginazione, checkpoint/resume, retry, finestre.

Nessuna chiamata di rete reale: si usa ``httpx.MockTransport``.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from nvdlocal.config import META_FULL_SYNC_INDEX, META_LAST_SYNC
from nvdlocal.db import count_cves, get_meta, set_meta
from nvdlocal.sync import (
    NVDClient,
    NVDError,
    NetworkError,
    sync_full,
    sync_incremental,
    windows,
)

from .conftest import vulnerabilities


def _page(items: list, total: int, start_index: int, per_page: int) -> dict:
    return {
        "resultsPerPage": per_page,
        "startIndex": start_index,
        "totalResults": total,
        "vulnerabilities": items,
    }


def _client(handler) -> NVDClient:
    """Client senza pause, con trasporto simulato."""
    transport = httpx.MockTransport(handler)
    return NVDClient(delay=0.0, client=httpx.Client(transport=transport))


@pytest.fixture
def all_items() -> list:
    items = []
    for name in ("cve_exact_version.json", "cve_version_range.json", "cve_and_configuration.json"):
        items.extend(vulnerabilities(name))
    return items


def test_sync_full_paginates(empty_db: sqlite3.Connection, all_items: list) -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["startIndex"])
        calls.append(start)
        return httpx.Response(200, json=_page(all_items[start : start + 1], 3, start, 1))

    with _client(handler) as client:
        stats = sync_full(empty_db, client, results_per_page=1)

    assert calls == [0, 1, 2]
    assert stats.pages == 3
    assert stats.completed is True
    assert count_cves(empty_db) == 3
    assert get_meta(empty_db, META_FULL_SYNC_INDEX) == "0"  # checkpoint azzerato
    assert get_meta(empty_db, META_LAST_SYNC)


def test_sync_full_max_pages_stops_early(
    empty_db: sqlite3.Connection, all_items: list
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["startIndex"])
        return httpx.Response(200, json=_page(all_items[start : start + 1], 3, start, 1))

    with _client(handler) as client:
        stats = sync_full(empty_db, client, results_per_page=1, max_pages=2)

    assert stats.pages == 2
    assert stats.completed is False
    assert count_cves(empty_db) == 2
    assert get_meta(empty_db, META_FULL_SYNC_INDEX) == "2"


def test_sync_full_resume(empty_db: sqlite3.Connection, all_items: list) -> None:
    """--resume riparte dallo startIndex salvato, senza riscaricare le pagine gia' viste."""
    with empty_db:
        set_meta(empty_db, META_FULL_SYNC_INDEX, "2")

    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["startIndex"])
        calls.append(start)
        return httpx.Response(200, json=_page(all_items[start : start + 1], 3, start, 1))

    with _client(handler) as client:
        stats = sync_full(empty_db, client, resume=True, results_per_page=1)

    assert calls == [2]
    assert stats.completed is True
    assert count_cves(empty_db) == 1


def test_sync_full_advances_by_items_received(
    empty_db: sqlite3.Connection, all_items: list
) -> None:
    """Una pagina piu' corta del resultsPerPage dichiarato non deve saltare record.

    Regressione: fidandosi del resultsPerPage dichiarato invece che degli
    elementi effettivamente ricevuti, la sync saltava i record mancanti e per
    giunta si dichiarava completata.
    """
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["startIndex"])
        seen.append(start)
        return httpx.Response(
            200,
            json={
                "resultsPerPage": 2000,  # dichiarato...
                "startIndex": start,
                "totalResults": len(all_items),
                "vulnerabilities": all_items[start : start + 1],  # ...ma ne arriva 1
            },
        )

    with _client(handler) as client:
        stats = sync_full(empty_db, client, results_per_page=2000)

    assert seen == list(range(len(all_items)))
    assert count_cves(empty_db) == len(all_items)
    assert stats.completed is True


def test_sync_incremental_advances_by_items_received(
    empty_db: sqlite3.Connection, all_items: list
) -> None:
    """Stessa regressione, sul percorso incrementale."""
    recent = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.000"
    )
    with empty_db:
        set_meta(empty_db, META_LAST_SYNC, recent)

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["startIndex"])
        return httpx.Response(
            200,
            json={
                "resultsPerPage": 2000,
                "startIndex": start,
                "totalResults": len(all_items),
                "vulnerabilities": all_items[start : start + 1],
            },
        )

    with _client(handler) as client:
        sync_incremental(empty_db, client)

    assert count_cves(empty_db) == len(all_items)


def test_sync_full_handles_empty_page(empty_db: sqlite3.Connection) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_page([], 0, 0, 2000))

    with _client(handler) as client:
        stats = sync_full(empty_db, client)

    assert stats.cves == 0
    assert stats.completed is True


def test_retry_then_success(empty_db: sqlite3.Connection, all_items: list, monkeypatch) -> None:
    """503 e 429 sono ritentati con backoff prima di arrendersi."""
    monkeypatch.setattr("nvdlocal.sync.time.sleep", lambda _: None)
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(503)
        if attempts["n"] == 2:
            return httpx.Response(429)
        return httpx.Response(200, json=_page(all_items[:1], 1, 0, 2000))

    with _client(handler) as client:
        stats = sync_full(empty_db, client)

    assert attempts["n"] == 3
    assert stats.completed is True
    assert count_cves(empty_db) == 1


def test_retry_gives_up_with_clear_error(monkeypatch) -> None:
    monkeypatch.setattr("nvdlocal.sync.time.sleep", lambda _: None)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with _client(handler) as client:
        with pytest.raises(NetworkError) as excinfo:
            client.get_json("https://services.nvd.nist.gov/rest/json/cves/2.0")

    assert "tentativi" in str(excinfo.value)


def test_timeout_is_retried(monkeypatch) -> None:
    monkeypatch.setattr("nvdlocal.sync.time.sleep", lambda _: None)
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise httpx.ConnectTimeout("timeout simulato")
        return httpx.Response(200, json={"ok": True})

    with _client(handler) as client:
        assert client.get_json("https://example.invalid") == {"ok": True}
    assert attempts["n"] == 3


def test_unexpected_status_is_not_retried() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    with _client(handler) as client:
        with pytest.raises(NVDError):
            client.get_json("https://example.invalid")


def test_api_key_is_sent_in_header() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    client = NVDClient(
        api_key="chiave-di-test",
        delay=0.0,
        client=httpx.Client(transport=transport, headers={"apiKey": "chiave-di-test"}),
    )
    with client:
        client.get_json("https://example.invalid")
    assert seen["apikey"] == "chiave-di-test"


def test_delay_depends_on_api_key() -> None:
    assert NVDClient(api_key=None, client=httpx.Client()).delay == 6.0
    assert NVDClient(api_key="x", client=httpx.Client()).delay == 0.8


# --------------------------------------------------------------------------- #
# Finestre temporali della sync incrementale
# --------------------------------------------------------------------------- #
def test_windows_splits_over_120_days() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=300)
    result = list(windows(start, end))

    assert len(result) == 3
    assert result[0][0] == start
    assert result[-1][1] == end
    for window_start, window_end in result:
        assert (window_end - window_start) <= timedelta(days=120)
    # Le finestre sono contigue.
    assert result[0][1] == result[1][0]
    assert result[1][1] == result[2][0]


def test_windows_single_window() -> None:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert list(windows(start, start + timedelta(days=10))) == [
        (start, start + timedelta(days=10))
    ]


def test_windows_empty_when_up_to_date() -> None:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert list(windows(now, now)) == []


def test_sync_incremental_uses_last_mod_dates(
    empty_db: sqlite3.Connection, all_items: list
) -> None:
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).strftime(
        "%Y-%m-%dT%H:%M:%S.000"
    )
    with empty_db:
        set_meta(empty_db, META_LAST_SYNC, recent)

    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        return httpx.Response(200, json=_page(all_items[:2], 2, 0, 2000))

    with _client(handler) as client:
        stats = sync_incremental(empty_db, client)

    assert len(seen) == 1
    assert "lastModStartDate" in seen[0] and "lastModEndDate" in seen[0]
    assert seen[0]["lastModStartDate"].endswith(".000")
    assert stats.cves == 2
    assert get_meta(empty_db, META_LAST_SYNC) != recent


def test_sync_incremental_splits_old_window(
    empty_db: sqlite3.Connection, all_items: list
) -> None:
    old = (datetime.now(timezone.utc) - timedelta(days=250)).strftime(
        "%Y-%m-%dT%H:%M:%S.000"
    )
    with empty_db:
        set_meta(empty_db, META_LAST_SYNC, old)

    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        return httpx.Response(200, json=_page([], 0, 0, 2000))

    with _client(handler) as client:
        sync_incremental(empty_db, client)

    assert len(seen) == 3  # 250 giorni -> 3 finestre da max 120


def test_sync_incremental_without_previous_sync(empty_db: sqlite3.Connection) -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("non deve essere chiamato")

    with _client(handler) as client:
        with pytest.raises(NVDError) as excinfo:
            sync_incremental(empty_db, client)
    assert "sync --full" in str(excinfo.value)
