"""Test dello schema, del parsing della risposta NVD e dell'upsert idempotente."""

from __future__ import annotations

import json
import sqlite3

import pytest

from nvdlocal.db import (
    DatabaseNotFoundError,
    connect,
    count_cves,
    get_meta,
    parse_cve_item,
    set_meta,
    upsert_cves,
)

from .conftest import FIXTURE_FILES, vulnerabilities


def _cpe_rows(conn: sqlite3.Connection, cve_id: str) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) AS n FROM cpe_match WHERE cve_id = ?", (cve_id,)
        ).fetchone()["n"]
    )


# --------------------------------------------------------------------------- #
# Idempotenza
# --------------------------------------------------------------------------- #
def test_upsert_is_idempotent(empty_db: sqlite3.Connection) -> None:
    """Sincronizzare due volte la stessa CVE non duplica le righe cpe_match."""
    items = vulnerabilities("cve_and_configuration.json")

    upsert_cves(empty_db, items)
    first_cves = count_cves(empty_db)
    first_rows = _cpe_rows(empty_db, "CVE-2019-0232")

    upsert_cves(empty_db, items)
    upsert_cves(empty_db, items)

    assert count_cves(empty_db) == first_cves == 1
    assert _cpe_rows(empty_db, "CVE-2019-0232") == first_rows == 4


def test_upsert_replaces_stale_configurations(empty_db: sqlite3.Connection) -> None:
    """Le configurazioni cambiano nel tempo: l'upsert le sostituisce, non le somma."""
    items = vulnerabilities("cve_exact_version.json")
    upsert_cves(empty_db, items)
    assert _cpe_rows(empty_db, "CVE-2021-41773") == 1

    updated = json.loads(json.dumps(items))
    node = updated[0]["cve"]["configurations"][0]["nodes"][0]
    node["cpeMatch"].append(
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*",
        }
    )
    upsert_cves(empty_db, updated)

    assert _cpe_rows(empty_db, "CVE-2021-41773") == 2
    assert count_cves(empty_db) == 1


def test_upsert_updates_scalar_fields(empty_db: sqlite3.Connection) -> None:
    items = json.loads(json.dumps(vulnerabilities("cve_exact_version.json")))
    upsert_cves(empty_db, items)

    items[0]["cve"]["vulnStatus"] = "Analyzed"
    items[0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 9.1
    items[0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"] = "CRITICAL"
    upsert_cves(empty_db, items)

    row = empty_db.execute("SELECT * FROM cve WHERE cve_id = 'CVE-2021-41773'").fetchone()
    assert row["vuln_status"] == "Analyzed"
    assert row["cvss_score"] == 9.1
    assert row["cvss_severity"] == "CRITICAL"


def test_all_fixtures_load(db: sqlite3.Connection) -> None:
    assert count_cves(db) == 6  # 5 file, uno contiene due CVE
    assert db.execute("SELECT COUNT(*) AS n FROM cpe_match").fetchone()["n"] == 7


# --------------------------------------------------------------------------- #
# Parsing della risposta NVD
# --------------------------------------------------------------------------- #
def test_parse_cve_item_extracts_fields() -> None:
    item = vulnerabilities("cve_exact_version.json")[0]
    cve_row, cpe_rows = parse_cve_item(item)

    assert cve_row[0] == "CVE-2021-41773"
    assert cve_row[3] == "Modified"
    assert cve_row[4].startswith("A flaw was found")  # descrizione inglese
    assert cve_row[5] == "3.1"
    assert cve_row[6] == 7.5
    assert cve_row[7] == "HIGH"
    assert cve_row[9] == "CWE-22"
    assert json.loads(cve_row[10])[0]["url"].startswith("https://httpd.apache.org")
    assert json.loads(cve_row[11])["cve"]["id"] == "CVE-2021-41773"  # raw_json

    assert len(cpe_rows) == 1
    assert cpe_rows[0][9] == "apache"  # vendor normalizzato
    assert cpe_rows[0][10] == "http_server"


def test_parse_cve_item_without_configurations() -> None:
    item = vulnerabilities("cve_no_configurations.json")[0]
    cve_row, cpe_rows = parse_cve_item(item)
    assert cve_row[0] == "CVE-2023-4128"
    assert cve_row[5] is None  # nessuna metrica
    assert cpe_rows == []


def test_parse_cve_item_and_configuration_flags() -> None:
    item = vulnerabilities("cve_and_configuration.json")[0]
    _, cpe_rows = parse_cve_item(item)
    assert len(cpe_rows) == 4
    assert {row[3] for row in cpe_rows} == {"AND"}  # config_operator
    assert {row[2] for row in cpe_rows} == {0, 1}  # due nodi distinti
    assert sorted(row[6] for row in cpe_rows) == [0, 1, 1, 1]  # un solo non-vulnerabile


def test_parse_cve_item_requires_id() -> None:
    with pytest.raises(ValueError):
        parse_cve_item({"cve": {}})


def test_malformed_items_are_skipped(empty_db: sqlite3.Connection) -> None:
    items = vulnerabilities("cve_exact_version.json") + [{"cve": {}}, {}]
    assert upsert_cves(empty_db, items) == 1


@pytest.mark.parametrize(
    "metrics,expected",
    [
        (
            {
                "cvssMetricV40": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL", "version": "4.0"}}],
                "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "version": "3.1"}}],
            },
            ("4.0", 9.3, "CRITICAL"),
        ),
        (
            {
                "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "version": "3.1"}}],
                "cvssMetricV30": [{"cvssData": {"baseScore": 6.0, "baseSeverity": "MEDIUM", "version": "3.0"}}],
                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
            },
            ("3.1", 7.5, "HIGH"),
        ),
        (
            {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "version": "2.0"}, "baseSeverity": "MEDIUM"}]},
            ("2.0", 5.0, "MEDIUM"),
        ),
        ({}, (None, None, None)),
    ],
)
def test_metric_priority(metrics: dict, expected: tuple) -> None:
    """v4.0 > v3.1 > v3.0 > v2, con la severita' v2 letta fuori da cvssData."""
    item = {"cve": {"id": "CVE-0000-0001", "metrics": metrics}}
    cve_row, _ = parse_cve_item(item)
    assert (cve_row[5], cve_row[6], cve_row[7]) == expected


def test_primary_metric_is_preferred() -> None:
    metrics = {
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 4.0, "baseSeverity": "MEDIUM", "version": "3.1"}},
            {"type": "Primary", "cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH", "version": "3.1"}},
        ]
    }
    cve_row, _ = parse_cve_item({"cve": {"id": "CVE-0000-0002", "metrics": metrics}})
    assert cve_row[6] == 8.8


def test_invalid_cpe_criteria_is_skipped() -> None:
    item = {
        "cve": {
            "id": "CVE-0000-0003",
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "non-un-cpe"},
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*",
                                },
                            ],
                        }
                    ]
                }
            ],
        }
    }
    _, cpe_rows = parse_cve_item(item)
    assert len(cpe_rows) == 1


# --------------------------------------------------------------------------- #
# Connessione e meta
# --------------------------------------------------------------------------- #
def test_connect_missing_database(tmp_path) -> None:
    with pytest.raises(DatabaseNotFoundError) as excinfo:
        connect(tmp_path / "assente.db")
    assert "sync --full" in str(excinfo.value)


def test_connect_creates_database(tmp_path) -> None:
    path = tmp_path / "nuovo" / "nvd.db"
    conn = connect(path, create=True)
    try:
        assert path.exists()
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    finally:
        conn.close()


def test_meta_roundtrip(empty_db: sqlite3.Connection) -> None:
    assert get_meta(empty_db, "chiave_assente") is None
    set_meta(empty_db, "chiave", "valore")
    set_meta(empty_db, "chiave", "nuovo_valore")
    assert get_meta(empty_db, "chiave") == "nuovo_valore"


def test_schema_version_is_recorded(empty_db: sqlite3.Connection) -> None:
    assert get_meta(empty_db, "schema_version") == "1"


def test_fixture_files_are_all_used() -> None:
    assert len(FIXTURE_FILES) == 5
