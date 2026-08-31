"""Motore di matching ``(vendor?, product, version)`` -> CVE applicabili.

La logica applicata a ogni riga ``cpe_match`` e' documentata in
:func:`evaluate_row`; il risultato distingue quattro ``match_type`` con livelli
di confidenza diversi (vedi README).
"""

from __future__ import annotations

import sqlite3
from enum import Enum
from typing import Any, Iterable, Sequence

from pydantic import BaseModel, Field

from . import versions
from .config import get_logger
from .cpe import InvalidCPEError, expand_alias, normalize_name, parse_cpe23

__all__ = [
    "AmbiguousProductError",
    "MatchResult",
    "MatchType",
    "ProductCandidate",
    "SearchFilters",
    "UnknownProductError",
    "evaluate_row",
    "resolve_candidates",
    "search",
    "severity_rank",
]

LOG = get_logger()

#: Ordinamento delle severita' CVSS (usato da ``--min-severity`` e dall'exit code).
SEVERITY_ORDER: dict[str, int] = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class MatchType(str, Enum):
    """Tipo di corrispondenza fra la versione cercata e la riga ``cpe_match``."""

    EXACT = "exact"
    RANGE = "range"
    ALL_VERSIONS = "all_versions"
    CONDITIONAL = "conditional"


#: Confidenza decrescente: usata per deduplicare piu' righe della stessa CVE.
_MATCH_CONFIDENCE: dict[MatchType, int] = {
    MatchType.EXACT: 3,
    MatchType.RANGE: 2,
    MatchType.ALL_VERSIONS: 1,
    MatchType.CONDITIONAL: 0,
}


def severity_rank(severity: str | None) -> int:
    """Rango numerico di una severita' CVSS (sconosciuta -> 0)."""
    return SEVERITY_ORDER.get((severity or "").upper(), 0)


class UnknownProductError(LookupError):
    """Nessun prodotto nel database corrisponde al termine cercato."""

    def __init__(self, term: str) -> None:
        super().__init__(
            f"nessun prodotto trovato per {term!r}. "
            "Prova 'nvdlocal resolve' con un termine piu' generico."
        )
        self.term = term


class AmbiguousProductError(LookupError):
    """Il termine cercato corrisponde a piu' ``vendor:product``: non si indovina."""

    def __init__(self, term: str, candidates: Sequence["ProductCandidate"]) -> None:
        super().__init__(
            f"il termine {term!r} corrisponde a {len(candidates)} prodotti distinti: "
            "rilancia specificando --vendor oppure --cpe."
        )
        self.term = term
        self.candidates = list(candidates)


class ProductCandidate(BaseModel):
    """Un ``vendor:product`` candidato con il numero di CVE associate."""

    vendor: str
    product: str
    cve_count: int = 0

    @property
    def key(self) -> str:
        """Chiave ``vendor:product``."""
        return f"{self.vendor}:{self.product}"


class SearchFilters(BaseModel):
    """Filtri applicati ai risultati di una ricerca."""

    min_severity: str | None = None
    min_score: float | None = None
    only_kev: bool = False
    min_epss: float | None = None
    include_all_versions: bool = True

    def keep(self, result: "MatchResult") -> bool:
        """True se il risultato supera tutti i filtri attivi."""
        # Si guarda version_match e non match_type: un match condizionale puo'
        # avere comunque un CPE senza versione, e va escluso anche quello.
        if not self.include_all_versions and result.version_match is MatchType.ALL_VERSIONS:
            return False
        if self.min_severity and severity_rank(result.cvss_severity) < severity_rank(
            self.min_severity
        ):
            return False
        if self.min_score is not None and (result.cvss_score or 0.0) < self.min_score:
            return False
        if self.only_kev and not result.kev:
            return False
        if self.min_epss is not None and (result.epss_score or 0.0) < self.min_epss:
            return False
        return True


class MatchResult(BaseModel):
    """Una CVE applicabile al software cercato, con il contesto del match."""

    cve_id: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwe: str = ""
    published: str | None = None
    last_modified: str | None = None
    vuln_status: str | None = None
    description: str = ""

    kev: bool = False
    kev_date_added: str | None = None
    kev_ransomware: str | None = None
    kev_due_date: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None

    match_type: MatchType
    #: Motivo del match a livello di versione, anche quando ``match_type`` e'
    #: ``conditional`` (che descrive invece la configurazione padre).
    version_match: MatchType
    criteria: str
    version_range: str = "*"
    #: Altri CPE che compongono la condizione AND, per i match condizionali.
    conditions: list[str] = Field(default_factory=list)

    @property
    def is_high_or_above(self) -> bool:
        """True se la severita' e' HIGH o CRITICAL (rilevante per l'exit code)."""
        return severity_rank(self.cvss_severity) >= SEVERITY_ORDER["HIGH"]


_SELECT_SQL = """
SELECT m.cve_id, m.config_index, m.node_index, m.config_operator, m.node_operator,
       m.negate, m.vulnerable, m.criteria, m.vendor, m.product, m.version,
       m.version_start_including, m.version_start_excluding,
       m.version_end_including, m.version_end_excluding,
       c.published, c.last_modified, c.vuln_status, c.description,
       c.cvss_version, c.cvss_score, c.cvss_severity, c.cvss_vector, c.cwe,
       k.cve_id AS kev_id, k.date_added AS kev_date_added,
       k.ransomware AS kev_ransomware, k.due_date AS kev_due_date,
       e.score AS epss_score, e.percentile AS epss_percentile
FROM cpe_match m
JOIN cve c ON c.cve_id = m.cve_id
LEFT JOIN kev k ON k.cve_id = m.cve_id
LEFT JOIN epss e ON e.cve_id = m.cve_id
WHERE m.vulnerable = 1 AND ({predicate})
"""


# --------------------------------------------------------------------------- #
# Risoluzione del nome prodotto
# --------------------------------------------------------------------------- #
def resolve_candidates(
    conn: sqlite3.Connection, term: str, vendor: str | None = None
) -> list[ProductCandidate]:
    """Trova i ``vendor:product`` compatibili con un termine di ricerca.

    Ordine di risoluzione: alias noti, poi match esatto sul prodotto
    normalizzato, poi ricerca ``LIKE %termine%`` su vendor e product.
    I candidati sono ordinati per numero di CVE associate (decrescente).
    """
    product_term = normalize_name(term)
    vendor_term = normalize_name(vendor) if vendor else None
    if not product_term:
        return []

    aliases = expand_alias(product_term)
    if aliases:
        pairs = [
            (v, p) for v, p in aliases if vendor_term is None or v == vendor_term
        ]
        candidates = _candidates_for_pairs(conn, pairs)
        if candidates:
            return candidates

    exact = _query_candidates(
        conn,
        "m.product = ?" + (" AND m.vendor = ?" if vendor_term else ""),
        (product_term, vendor_term) if vendor_term else (product_term,),
    )
    if exact:
        return exact

    # Ricerca LIKE su "vendor:product": ogni parola del termine deve comparire,
    # cosi' "apache http" trova apache:http_server.
    words = [w for w in product_term.split("_") if w]
    if not words:
        return []
    predicate = " AND ".join(
        ["(m.vendor || ':' || m.product) LIKE ? ESCAPE '\\'"] * len(words)
    )
    params: tuple[Any, ...] = tuple(f"%{_escape_like(word)}%" for word in words)
    if vendor_term:
        predicate += " AND m.vendor = ?"
        params += (vendor_term,)
    return _query_candidates(conn, predicate, params)


def _escape_like(value: str) -> str:
    """Neutralizza i metacaratteri LIKE (``%``, ``_``) nel termine di ricerca."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _query_candidates(
    conn: sqlite3.Connection, predicate: str, params: tuple[Any, ...]
) -> list[ProductCandidate]:
    sql = (
        "SELECT m.vendor AS vendor, m.product AS product, "
        "COUNT(DISTINCT m.cve_id) AS cve_count "
        f"FROM cpe_match m WHERE {predicate} "
        "GROUP BY m.vendor, m.product ORDER BY cve_count DESC, m.vendor, m.product"
    )
    return [
        ProductCandidate(
            vendor=row["vendor"] or "", product=row["product"] or "", cve_count=row["cve_count"]
        )
        for row in conn.execute(sql, params)
    ]


def _pair_exists(conn: sqlite3.Connection, pair: tuple[str, str]) -> bool:
    """True se il database contiene almeno una riga per quel ``vendor:product``."""
    row = conn.execute(
        "SELECT 1 FROM cpe_match WHERE vendor = ? AND product = ? LIMIT 1", pair
    ).fetchone()
    return row is not None


def _candidates_for_pairs(
    conn: sqlite3.Connection, pairs: Sequence[tuple[str, str]]
) -> list[ProductCandidate]:
    if not pairs:
        return []
    predicate = " OR ".join(["(m.vendor = ? AND m.product = ?)"] * len(pairs))
    params = tuple(value for pair in pairs for value in pair)
    return _query_candidates(conn, predicate, params)


# --------------------------------------------------------------------------- #
# Valutazione di una singola riga cpe_match
# --------------------------------------------------------------------------- #
def _satisfies_ranges(version: str, row: Any) -> bool:
    """Verifica i quattro vincoli di range (in AND) contro la versione cercata."""
    checks = (
        ("version_start_including", lambda c: c >= 0),
        ("version_start_excluding", lambda c: c > 0),
        ("version_end_including", lambda c: c <= 0),
        ("version_end_excluding", lambda c: c < 0),
    )
    for field, predicate in checks:
        bound = row[field]
        if not versions.is_concrete(bound):
            continue
        try:
            comparison = versions.compare(version, str(bound))
        except ValueError:
            LOG.debug("vincolo non confrontabile %s=%r su %s", field, bound, row["cve_id"])
            return False
        if not predicate(comparison):
            return False
    return True


def _has_range(row: Any) -> bool:
    return any(
        versions.is_concrete(row[field])
        for field in (
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
        )
    )


def evaluate_row(row: Any, version: str) -> MatchType | None:
    """Decide se una riga ``cpe_match`` copre la versione cercata.

    Regole (nell'ordine):

    1. le righe con ``vulnerable = 0`` sono scartate: descrivono condizioni
       ambientali ("running on"), non il componente vulnerabile;
    2. le righe di un nodo negato (``negate = 1``) sono scartate;
    3. versione CPE concreta -> match solo se identica alla versione cercata
       (:data:`MatchType.EXACT`);
    4. versione CPE ``*`` con almeno un vincolo di range -> i vincoli presenti
       vanno soddisfatti tutti in AND (:data:`MatchType.RANGE`);
    5. versione CPE ``*`` senza vincoli -> match su tutte le versioni
       (:data:`MatchType.ALL_VERSIONS`);
    6. versione CPE ``-`` (NA) senza vincoli -> nessun match.

    :return: il tipo di match a livello di versione, oppure ``None``.
    """
    if not row["vulnerable"] or row["negate"]:
        return None

    cpe_version = row["version"]
    if versions.is_concrete(cpe_version):
        try:
            if versions.compare(version, str(cpe_version)) == 0:
                return MatchType.EXACT
        except ValueError:
            LOG.debug("versione non confrontabile: %r vs %r", version, cpe_version)
        return None

    if _has_range(row):
        return MatchType.RANGE if _satisfies_ranges(version, row) else None

    # Versione NA (``-``) e nessun vincolo: la riga non esprime una versione.
    if versions.is_na(cpe_version):
        return None
    return MatchType.ALL_VERSIONS


def describe_range(row: Any) -> str:
    """Descrizione leggibile del range di versioni coperto dalla riga."""
    if versions.is_concrete(row["version"]):
        return f"= {row['version']}"
    parts: list[str] = []
    for field, symbol in (
        ("version_start_including", ">="),
        ("version_start_excluding", ">"),
        ("version_end_including", "<="),
        ("version_end_excluding", "<"),
    ):
        bound = row[field]
        if versions.is_concrete(bound):
            parts.append(f"{symbol} {bound}")
    return ", ".join(parts) if parts else "* (tutte le versioni)"


# --------------------------------------------------------------------------- #
# Contesto delle configurazioni AND
# --------------------------------------------------------------------------- #
def _configuration_context(
    conn: sqlite3.Connection, cve_id: str, config_index: int
) -> tuple[bool, dict[int, list[str]]]:
    """Determina se una configurazione e' un AND multi-nodo e i CPE per nodo.

    :return: ``(is_conditional, {node_index: [criteria, ...]})``.
    """
    rows = conn.execute(
        "SELECT node_index, config_operator, criteria FROM cpe_match "
        "WHERE cve_id = ? AND config_index = ?",
        (cve_id, config_index),
    ).fetchall()
    by_node: dict[int, list[str]] = {}
    operators: set[str] = set()
    for row in rows:
        operators.add((row["config_operator"] or "").upper())
        criteria = by_node.setdefault(row["node_index"], [])
        if row["criteria"] not in criteria:
            criteria.append(row["criteria"])
    return ("AND" in operators and len(by_node) > 1), by_node


# --------------------------------------------------------------------------- #
# Ricerca
# --------------------------------------------------------------------------- #
def _row_to_result(
    row: Any, version_match: MatchType, match_type: MatchType, conditions: list[str]
) -> MatchResult:
    return MatchResult(
        cve_id=row["cve_id"],
        cvss_score=row["cvss_score"],
        cvss_severity=row["cvss_severity"],
        cvss_vector=row["cvss_vector"],
        cvss_version=row["cvss_version"],
        cwe=row["cwe"] or "",
        published=row["published"],
        last_modified=row["last_modified"],
        vuln_status=row["vuln_status"],
        description=row["description"] or "",
        kev=bool(row["kev_id"]),
        kev_date_added=row["kev_date_added"],
        kev_ransomware=row["kev_ransomware"],
        kev_due_date=row["kev_due_date"],
        epss_score=row["epss_score"],
        epss_percentile=row["epss_percentile"],
        match_type=match_type,
        version_match=version_match,
        criteria=row["criteria"],
        version_range=describe_range(row),
        conditions=conditions,
    )


def _sort_key(result: MatchResult) -> tuple[float, str]:
    """Ordinamento: score decrescente, poi data di pubblicazione decrescente."""
    return (-(result.cvss_score or 0.0), _invert(result.published or ""))


def _invert(text: str) -> str:
    """Chiave che inverte l'ordinamento lessicografico di una data ISO."""
    return "".join(chr(0x10FFFF - ord(ch)) if ord(ch) < 0x10FFFF else ch for ch in text)


def search(
    conn: sqlite3.Connection,
    version: str,
    product: str | None = None,
    vendor: str | None = None,
    cpe: str | None = None,
    filters: SearchFilters | None = None,
) -> list[MatchResult]:
    """Cerca le CVE applicabili a un software in una versione specifica.

    :param version: versione del software (obbligatoria).
    :param product: nome del prodotto, anche in forma di alias (``httpd``).
    :param vendor: vendor, per disambiguare.
    :param cpe: in alternativa a product/vendor, un CPE 2.3 completo.
    :raises ValueError: se la versione non e' confrontabile.
    :raises UnknownProductError: se nessun prodotto corrisponde.
    :raises AmbiguousProductError: se il termine e' ambiguo e manca il vendor.
    """
    # Una versione non confrontabile (vuota, o i valori speciali CPE * e -)
    # non deve passare in silenzio: senza questo controllo la ricerca
    # restituirebbe comunque i match all_versions, che sembrano una risposta
    # vera mentre in realta' non e' stato confrontato nulla.
    if versions.is_special(version) or not versions.tokenize(version):
        raise ValueError(
            f"versione non valida: {version!r}. Indica una versione concreta "
            "(es. 2.4.52); i valori speciali CPE '*' e '-' non sono versioni."
        )

    filters = filters or SearchFilters()
    pairs = _target_pairs(conn, product=product, vendor=vendor, cpe=cpe)

    predicate = " OR ".join(["(m.vendor = ? AND m.product = ?)"] * len(pairs))
    params = tuple(value for pair in pairs for value in pair)
    rows = conn.execute(_SELECT_SQL.format(predicate=predicate), params).fetchall()

    best: dict[str, MatchResult] = {}
    context_cache: dict[tuple[str, int], tuple[bool, dict[int, list[str]]]] = {}

    for row in rows:
        version_match = evaluate_row(row, version)
        if version_match is None:
            continue

        key = (row["cve_id"], row["config_index"])
        if key not in context_cache:
            context_cache[key] = _configuration_context(conn, key[0], key[1])
        is_conditional, by_node = context_cache[key]

        if is_conditional:
            # In una configurazione AND i nodi si sommano, mentre i CPE dentro
            # lo stesso nodo (OR) sono alternative: la condizione sono gli
            # *altri* nodi, non i fratelli dello stesso nodo.
            match_type = MatchType.CONDITIONAL
            conditions = [
                criteria
                for node_index, node_criteria in sorted(by_node.items())
                if node_index != row["node_index"]
                for criteria in node_criteria
            ]
        else:
            match_type = version_match
            conditions = []

        result = _row_to_result(row, version_match, match_type, conditions)
        current = best.get(result.cve_id)
        if current is None or _MATCH_CONFIDENCE[result.match_type] > _MATCH_CONFIDENCE[
            current.match_type
        ]:
            best[result.cve_id] = result

    results = [r for r in best.values() if filters.keep(r)]
    results.sort(key=_sort_key)
    return results


def _target_pairs(
    conn: sqlite3.Connection,
    product: str | None,
    vendor: str | None,
    cpe: str | None,
) -> list[tuple[str, str]]:
    """Determina le coppie ``(vendor, product)`` su cui eseguire la ricerca."""
    if cpe:
        try:
            parsed = parse_cpe23(cpe)
        except InvalidCPEError as exc:
            raise ValueError(str(exc)) from exc
        if versions.is_special(parsed.product):
            raise ValueError(
                f"il CPE deve indicare un product concreto, trovato {parsed.product!r}: {cpe!r}"
            )
        if versions.is_special(parsed.vendor):
            # Vendor wildcard: si risolve per prodotto, con le stesse regole di
            # ambiguita' di --product, invece di cercare il vendor letterale '*'
            # (che non troverebbe mai nulla).
            product = parsed.product
            vendor = None
        else:
            pair = (normalize_name(parsed.vendor), normalize_name(parsed.product))
            # Un CPE con un vendor:product assente dal database non deve dare
            # "nessuna CVE": in un tool di sicurezza si legge come "host pulito",
            # mentre e' quasi sempre un refuso nel CPE.
            if not _pair_exists(conn, pair):
                raise UnknownProductError(f"{pair[0]}:{pair[1]}")
            return [pair]

    if not product:
        raise ValueError("serve --product oppure --cpe")

    candidates = resolve_candidates(conn, product, vendor)
    if not candidates:
        raise UnknownProductError(product)

    keys = {(c.vendor, c.product) for c in candidates}
    if len(keys) > 1 and not expand_alias(product):
        raise AmbiguousProductError(product, candidates)
    return sorted(keys)


def search_cves_for_cve_id(conn: sqlite3.Connection, cve_id: str) -> dict[str, Any] | None:
    """Recupera il dettaglio completo di una CVE (per il comando ``show``)."""
    row = conn.execute(
        "SELECT c.*, k.date_added AS kev_date_added, k.ransomware AS kev_ransomware, "
        "k.due_date AS kev_due_date, e.score AS epss_score, e.percentile AS epss_percentile "
        "FROM cve c "
        "LEFT JOIN kev k ON k.cve_id = c.cve_id "
        "LEFT JOIN epss e ON e.cve_id = c.cve_id "
        "WHERE c.cve_id = ?",
        (cve_id.upper(),),
    ).fetchone()
    if row is None:
        return None
    matches = conn.execute(
        "SELECT * FROM cpe_match WHERE cve_id = ? ORDER BY config_index, node_index, id",
        (cve_id.upper(),),
    ).fetchall()
    return {"cve": dict(row), "cpe_match": [dict(m) for m in matches]}


def high_or_above(results: Iterable[MatchResult]) -> bool:
    """True se almeno un risultato ha severita' HIGH o CRITICAL."""
    return any(r.is_high_or_above for r in results)


# --------------------------------------------------------------------------- #
# Elaborazione di un inventario (comando batch)
# --------------------------------------------------------------------------- #
class InventoryRow(BaseModel):
    """Una riga dell'inventario: ``host,port,vendor,product,version``."""

    host: str = ""
    port: str = ""
    vendor: str | None = None
    product: str = ""
    version: str = ""

    @property
    def software(self) -> str:
        """Etichetta leggibile del software (``vendor:product`` o solo product)."""
        return f"{self.vendor}:{self.product}" if self.vendor else self.product


class BatchFinding(BaseModel):
    """Una coppia (host, CVE) prodotta dall'elaborazione di un inventario."""

    host: str
    port: str
    software: str
    version: str
    result: MatchResult


class BatchUnresolved(BaseModel):
    """Una riga di inventario che non e' stato possibile risolvere."""

    host: str
    port: str
    vendor: str = ""
    product: str = ""
    version: str = ""
    reason: str
    candidates: list[str] = Field(default_factory=list)


def process_inventory(
    conn: sqlite3.Connection,
    rows: Iterable[InventoryRow],
    filters: SearchFilters | None = None,
) -> tuple[list[BatchFinding], list[BatchUnresolved]]:
    """Esegue una ricerca per ogni riga di inventario.

    :return: ``(findings, non_risolti)``; le righe ambigue, sconosciute o prive
        di versione finiscono fra i non risolti con la relativa motivazione.
    """
    findings: list[BatchFinding] = []
    unresolved: list[BatchUnresolved] = []

    def skipped(
        row: InventoryRow, reason: str, candidates: list[str] | None = None
    ) -> BatchUnresolved:
        return BatchUnresolved(
            host=row.host,
            port=row.port,
            vendor=row.vendor or "",
            product=row.product,
            version=row.version,
            reason=reason,
            candidates=candidates or [],
        )

    for row in rows:
        if not row.product or not row.version:
            unresolved.append(skipped(row, "product o version mancante"))
            continue
        try:
            results = search(
                conn,
                version=row.version,
                product=row.product,
                vendor=row.vendor,
                filters=filters,
            )
        except AmbiguousProductError as exc:
            unresolved.append(
                skipped(
                    row,
                    "prodotto ambiguo: specificare il vendor",
                    [c.key for c in exc.candidates[:10]],
                )
            )
            continue
        except UnknownProductError:
            unresolved.append(skipped(row, "prodotto non presente nel database NVD"))
            continue
        except ValueError as exc:
            unresolved.append(skipped(row, str(exc)))
            continue

        if not results:
            unresolved.append(skipped(row, "nessuna CVE applicabile a questa versione"))
            continue

        findings.extend(
            BatchFinding(
                host=row.host,
                port=row.port,
                software=row.software,
                version=row.version,
                result=result,
            )
            for result in results
        )

    return findings, unresolved
