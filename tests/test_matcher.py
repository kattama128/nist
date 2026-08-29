"""Test del motore di matching: i sei casi della logica + filtri e risoluzione nomi."""

from __future__ import annotations

import sqlite3

import pytest

from nvdlocal.matcher import (
    AmbiguousProductError,
    InventoryRow,
    MatchType,
    SearchFilters,
    UnknownProductError,
    evaluate_row,
    high_or_above,
    process_inventory,
    resolve_candidates,
    search,
    search_cves_for_cve_id,
    severity_rank,
)


def _ids(results: list) -> set[str]:
    return {r.cve_id for r in results}


def _by_id(results: list, cve_id: str):
    return next(r for r in results if r.cve_id == cve_id)


# --------------------------------------------------------------------------- #
# Caso 1: filtro su product (e vendor)
# --------------------------------------------------------------------------- #
def test_filter_by_product(db: sqlite3.Connection) -> None:
    results = search(db, version="2.4.49", product="http_server", vendor="apache")
    assert "CVE-2021-41773" in _ids(results)
    # Tomcat non deve comparire fra i risultati di http_server.
    assert "CVE-2019-0232" not in _ids(results)


def test_vendor_disambiguates(db: sqlite3.Connection) -> None:
    results = search(db, version="9.0.10", product="tomcat", vendor="apache")
    assert _ids(results) == {"CVE-2019-0232"}


# --------------------------------------------------------------------------- #
# Caso 2: le righe con vulnerable = 0 sono condizioni ambientali, non match
# --------------------------------------------------------------------------- #
def test_non_vulnerable_rows_are_discarded(db: sqlite3.Connection) -> None:
    """Windows compare in CVE-2019-0232 solo come 'running on' (vulnerable: false)."""
    row = db.execute(
        "SELECT * FROM cpe_match WHERE product = 'windows' AND cve_id = 'CVE-2019-0232'"
    ).fetchone()
    assert row is not None and row["vulnerable"] == 0

    # Il prodotto e' presente nel database (compare come condizione), ma non
    # produce match: la riga non descrive il componente vulnerabile.
    assert search(db, version="10", product="windows", vendor="microsoft") == []
    assert evaluate_row(row, "10") is None


# --------------------------------------------------------------------------- #
# Caso 3: versione CPE concreta -> match solo se identica
# --------------------------------------------------------------------------- #
def test_exact_version_match(db: sqlite3.Connection) -> None:
    results = search(db, version="2.4.49", product="http_server", vendor="apache")
    result = _by_id(results, "CVE-2021-41773")
    assert result.match_type is MatchType.EXACT
    assert result.criteria == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert result.version_range == "= 2.4.49"
    assert result.cvss_score == 7.5
    assert result.cvss_severity == "HIGH"
    assert result.cvss_version == "3.1"  # v3.1 ha priorita' su v2
    assert result.cwe == "CWE-22"


def test_exact_version_does_not_match_other_versions(db: sqlite3.Connection) -> None:
    results = search(db, version="2.4.48", product="http_server", vendor="apache")
    assert "CVE-2021-41773" not in _ids(results)


def test_exact_version_normalizes_equivalent_forms(db: sqlite3.Connection) -> None:
    """2.4.49 e 2.4.49.0 sono la stessa versione per il comparatore."""
    results = search(db, version="2.4.49.0", product="http_server", vendor="apache")
    assert "CVE-2021-41773" in _ids(results)


# --------------------------------------------------------------------------- #
# Caso 4: versione CPE '*' con vincoli di range
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "version,expected",
    [
        ("2.4.0", True),  # versionStartIncluding: incluso
        ("2.4.52", True),  # dentro il range
        ("2.4.53", False),  # versionEndExcluding: escluso
        ("2.4.54", False),  # oltre il range
        ("2.3.9", False),  # prima dell'inizio del range
    ],
)
def test_version_range_boundaries(
    db: sqlite3.Connection, version: str, expected: bool
) -> None:
    results = search(db, version=version, product="http_server", vendor="apache")
    assert ("CVE-2022-22720" in _ids(results)) is expected


def test_range_match_metadata(db: sqlite3.Connection) -> None:
    results = search(db, version="2.4.52", product="http_server", vendor="apache")
    result = _by_id(results, "CVE-2022-22720")
    assert result.match_type is MatchType.RANGE
    assert result.version_range == ">= 2.4.0, < 2.4.53"
    assert result.cvss_severity == "CRITICAL"


@pytest.mark.parametrize(
    "field,bound,version,expected",
    [
        ("version_start_including", "2.0", "2.0", True),
        ("version_start_including", "2.0", "1.9", False),
        ("version_start_excluding", "2.0", "2.0", False),
        ("version_start_excluding", "2.0", "2.0.1", True),
        ("version_end_including", "3.0", "3.0", True),
        ("version_end_including", "3.0", "3.0.1", False),
        ("version_end_excluding", "3.0", "2.9", True),
        ("version_end_excluding", "3.0", "3.0", False),
    ],
)
def test_all_four_range_constraints(
    empty_db: sqlite3.Connection, field: str, bound: str, version: str, expected: bool
) -> None:
    """Ogni vincolo di range e' valutato con il comparatore di versioni."""
    _insert_synthetic_match(empty_db, {field: bound})
    row = empty_db.execute("SELECT * FROM cpe_match").fetchone()
    assert (evaluate_row(row, version) is MatchType.RANGE) is expected


def test_range_constraints_are_combined_in_and(empty_db: sqlite3.Connection) -> None:
    _insert_synthetic_match(
        empty_db,
        {"version_start_including": "2.0", "version_end_excluding": "3.0"},
    )
    row = empty_db.execute("SELECT * FROM cpe_match").fetchone()
    assert evaluate_row(row, "2.5") is MatchType.RANGE
    assert evaluate_row(row, "1.9") is None
    assert evaluate_row(row, "3.0") is None


def _insert_synthetic_match(conn: sqlite3.Connection, bounds: dict[str, str]) -> None:
    """Inserisce una riga cpe_match minimale con i vincoli richiesti."""
    columns = {
        "cve_id": "CVE-0000-0000",
        "config_index": 0,
        "node_index": 0,
        "config_operator": None,
        "node_operator": "OR",
        "negate": 0,
        "vulnerable": 1,
        "criteria": "cpe:2.3:a:test:prodotto:*:*:*:*:*:*:*:*",
        "part": "a",
        "vendor": "test",
        "product": "prodotto",
        "version": "*",
        "version_start_including": None,
        "version_start_excluding": None,
        "version_end_including": None,
        "version_end_excluding": None,
    }
    columns.update(bounds)
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO cve (cve_id, cvss_severity) VALUES (?, ?)",
            ("CVE-0000-0000", "HIGH"),
        )
        conn.execute(
            f"INSERT INTO cpe_match ({', '.join(columns)}) "
            f"VALUES ({', '.join('?' * len(columns))})",
            tuple(columns.values()),
        )


# --------------------------------------------------------------------------- #
# Caso 5: versione CPE '*' senza vincoli -> all_versions
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("version", ["2.3.4", "3.0.5", "1.0"])
def test_all_versions_match(db: sqlite3.Connection, version: str) -> None:
    results = search(db, version=version, product="vsftpd")
    result = _by_id(results, "CVE-2011-2523")
    assert result.match_type is MatchType.ALL_VERSIONS
    assert result.version_range == "* (tutte le versioni)"


def test_all_versions_can_be_excluded(db: sqlite3.Connection) -> None:
    results = search(
        db,
        version="3.0.5",
        product="vsftpd",
        filters=SearchFilters(include_all_versions=False),
    )
    assert results == []


# --------------------------------------------------------------------------- #
# Caso 6: configurazione AND multi-nodo -> conditional
# --------------------------------------------------------------------------- #
def test_conditional_match(db: sqlite3.Connection) -> None:
    results = search(db, version="9.0.10", product="tomcat", vendor="apache")
    result = _by_id(results, "CVE-2019-0232")
    assert result.match_type is MatchType.CONDITIONAL
    # A livello di versione resta un match di tipo range.
    assert result.version_match is MatchType.RANGE
    # La condizione e' l'altro nodo dell'AND, non i CPE alternativi dello
    # stesso nodo OR (le altre release line di Tomcat).
    assert result.conditions == ["cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"]


def test_conditional_conditions_exclude_or_siblings(db: sqlite3.Connection) -> None:
    """I CPE fratelli dentro lo stesso nodo OR sono alternative, non requisiti."""
    with db:
        db.execute(
            "UPDATE cpe_match SET criteria = 'cpe:2.3:a:apache:tomcat:alt:*:*:*:*:*:*:*' "
            "WHERE cve_id = 'CVE-2019-0232' AND node_index = 0 "
            "AND version_start_including = '7.0.0'"
        )
    results = search(db, version="9.0.10", product="tomcat", vendor="apache")
    conditions = _by_id(results, "CVE-2019-0232").conditions
    assert all("tomcat" not in c for c in conditions)


def test_conditional_match_is_not_discarded(db: sqlite3.Connection) -> None:
    """Il match condizionale va riportato, non scartato e non dato per certo."""
    results = search(db, version="7.0.50", product="tomcat", vendor="apache")
    assert "CVE-2019-0232" in _ids(results)


def test_conditional_respects_version_bounds(db: sqlite3.Connection) -> None:
    results = search(db, version="9.0.18", product="tomcat", vendor="apache")
    assert "CVE-2019-0232" not in _ids(results)


# --------------------------------------------------------------------------- #
# CVE senza configurations
# --------------------------------------------------------------------------- #
def test_cve_without_configurations_has_no_cpe_rows(db: sqlite3.Connection) -> None:
    for cve_id in ("CVE-2023-4128", "CVE-2024-99999"):
        row = db.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,)).fetchone()
        assert row is not None
        count = db.execute(
            "SELECT COUNT(*) AS n FROM cpe_match WHERE cve_id = ?", (cve_id,)
        ).fetchone()["n"]
        assert count == 0


def test_rejected_cve_has_no_metrics(db: sqlite3.Connection) -> None:
    row = db.execute("SELECT * FROM cve WHERE cve_id = 'CVE-2023-4128'").fetchone()
    assert row["cvss_score"] is None
    assert row["vuln_status"] == "Rejected"


# --------------------------------------------------------------------------- #
# Risoluzione del nome prodotto
# --------------------------------------------------------------------------- #
def test_resolve_by_alias(db: sqlite3.Connection) -> None:
    candidates = resolve_candidates(db, "httpd")
    assert [(c.vendor, c.product) for c in candidates] == [("apache", "http_server")]
    assert candidates[0].cve_count == 2


def test_alias_search_without_vendor(db: sqlite3.Connection) -> None:
    """Un alias noto non e' ambiguo anche se mappa su piu' vendor:product."""
    results = search(db, version="2.4.49", product="httpd")
    assert "CVE-2021-41773" in _ids(results)


def test_resolve_partial_term(db: sqlite3.Connection) -> None:
    candidates = resolve_candidates(db, "apache")
    keys = {c.key for c in candidates}
    assert "apache:http_server" in keys
    assert "apache:tomcat" in keys
    # Ordinamento per numero di CVE decrescente.
    assert candidates == sorted(candidates, key=lambda c: -c.cve_count)


def test_ambiguous_term_is_not_guessed(db: sqlite3.Connection) -> None:
    with pytest.raises(AmbiguousProductError) as excinfo:
        search(db, version="2.4.49", product="apache")
    assert len(excinfo.value.candidates) >= 2
    assert "--vendor" in str(excinfo.value)


def test_unknown_product(db: sqlite3.Connection) -> None:
    with pytest.raises(UnknownProductError):
        search(db, version="1.0", product="software_inesistente_xyz")


def test_search_by_cpe(db: sqlite3.Connection) -> None:
    results = search(
        db,
        version="2.4.49",
        cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
    )
    assert "CVE-2021-41773" in _ids(results)


def test_search_requires_product_or_cpe(db: sqlite3.Connection) -> None:
    with pytest.raises(ValueError):
        search(db, version="1.0")


# --------------------------------------------------------------------------- #
# Filtri, ordinamento, arricchimento
# --------------------------------------------------------------------------- #
def test_results_sorted_by_score_then_date(db: sqlite3.Connection) -> None:
    results = search(db, version="2.4.52", product="http_server", vendor="apache")
    scores = [r.cvss_score or 0 for r in results]
    assert scores == sorted(scores, reverse=True)


def test_min_severity_filter(db: sqlite3.Connection) -> None:
    results = search(
        db,
        version="2.4.49",
        product="http_server",
        vendor="apache",
        filters=SearchFilters(min_severity="CRITICAL"),
    )
    assert "CVE-2021-41773" not in _ids(results)  # HIGH, sotto la soglia


def test_min_score_filter(db: sqlite3.Connection) -> None:
    results = search(
        db,
        version="2.4.49",
        product="http_server",
        vendor="apache",
        filters=SearchFilters(min_score=9.0),
    )
    assert all((r.cvss_score or 0) >= 9.0 for r in results)


def test_kev_and_epss_enrichment(enriched_db: sqlite3.Connection) -> None:
    results = search(enriched_db, version="2.4.49", product="http_server", vendor="apache")
    result = _by_id(results, "CVE-2021-41773")
    assert result.kev is True
    assert result.kev_ransomware == "Known"
    assert result.epss_score == pytest.approx(0.97542)


def test_only_kev_filter(enriched_db: sqlite3.Connection) -> None:
    results = search(
        enriched_db,
        version="2.4.49",
        product="http_server",
        vendor="apache",
        filters=SearchFilters(only_kev=True),
    )
    assert _ids(results) == {"CVE-2021-41773"}


def test_min_epss_filter(enriched_db: sqlite3.Connection) -> None:
    results = search(
        enriched_db,
        version="2.4.52",
        product="http_server",
        vendor="apache",
        filters=SearchFilters(min_epss=0.5),
    )
    assert results == []


def test_high_or_above_helper(db: sqlite3.Connection) -> None:
    results = search(db, version="2.4.49", product="http_server", vendor="apache")
    assert high_or_above(results) is True
    assert high_or_above([]) is False


def test_severity_rank_ordering() -> None:
    assert severity_rank("CRITICAL") > severity_rank("HIGH") > severity_rank("MEDIUM")
    assert severity_rank(None) == 0
    assert severity_rank("sconosciuta") == 0


# --------------------------------------------------------------------------- #
# Dettaglio CVE e batch
# --------------------------------------------------------------------------- #
def test_cve_detail(db: sqlite3.Connection) -> None:
    detail = search_cves_for_cve_id(db, "cve-2021-41773")
    assert detail is not None
    assert detail["cve"]["cve_id"] == "CVE-2021-41773"
    assert len(detail["cpe_match"]) == 1
    assert search_cves_for_cve_id(db, "CVE-1999-0001") is None


def test_process_inventory(db: sqlite3.Connection) -> None:
    rows = [
        InventoryRow(host="10.0.0.1", port="443", vendor="apache", product="http_server", version="2.4.52"),
        InventoryRow(host="10.0.0.2", port="8080", product="apache", version="2.4.52"),
        InventoryRow(host="10.0.0.3", port="21", product="software_inesistente_xyz", version="1.0"),
        InventoryRow(host="10.0.0.4", port="80", product="http_server", version=""),
    ]
    findings, unresolved = process_inventory(db, rows)

    assert {f.host for f in findings} == {"10.0.0.1"}
    reasons = {u.host: u.reason for u in unresolved}
    assert "ambiguo" in reasons["10.0.0.2"]
    assert "non presente" in reasons["10.0.0.3"]
    assert "mancante" in reasons["10.0.0.4"]

    ambiguous = next(u for u in unresolved if u.host == "10.0.0.2")
    assert ambiguous.candidates  # i candidati vengono riportati nel report
