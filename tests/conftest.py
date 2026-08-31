"""Fixture condivise: database in memoria popolato dalle risposte NVD ridotte.

Tutti i test girano offline: nessuna chiamata di rete.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator

import pytest

from nvdlocal.db import init_db, upsert_cves

FIXTURES = Path(__file__).parent / "fixtures"

#: Tutte le risposte NVD ridotte disponibili.
FIXTURE_FILES = (
    "cve_exact_version.json",
    "cve_version_range.json",
    "cve_and_configuration.json",
    "cve_no_configurations.json",
    "cve_all_versions.json",
)


def load_fixture(name: str) -> dict[str, Any]:
    """Carica una risposta NVD dalla directory ``fixtures``."""
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def vulnerabilities(name: str) -> list[dict[str, Any]]:
    """Elenco ``vulnerabilities`` di una fixture."""
    return load_fixture(name)["vulnerabilities"]


@pytest.fixture
def empty_db() -> Iterator[sqlite3.Connection]:
    """Database vuoto in memoria con lo schema applicato."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    init_db(conn)
    yield conn
    conn.close()


@pytest.fixture
def db(empty_db: sqlite3.Connection) -> sqlite3.Connection:
    """Database popolato con tutte le fixture NVD."""
    for name in FIXTURE_FILES:
        upsert_cves(empty_db, vulnerabilities(name))
    return empty_db


@pytest.fixture
def enriched_db(db: sqlite3.Connection) -> sqlite3.Connection:
    """Database con anche qualche riga KEV/EPSS, senza toccare la rete."""
    with db:
        db.execute(
            "INSERT INTO kev (cve_id, date_added, ransomware, due_date) VALUES (?, ?, ?, ?)",
            ("CVE-2021-41773", "2021-11-03", "Known", "2021-11-17"),
        )
        db.executemany(
            "INSERT INTO epss (cve_id, score, percentile, updated) VALUES (?, ?, ?, ?)",
            [
                ("CVE-2021-41773", 0.97542, 0.99981, "2026-08-29T00:00:00+0000"),
                ("CVE-2022-22720", 0.04211, 0.92150, "2026-08-29T00:00:00+0000"),
            ],
        )
    return db
