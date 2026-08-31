"""API HTTP opzionale (FastAPI) sopra il database locale.

Avviata da ``nvdlocal serve``. Ogni richiesta apre e chiude la propria
connessione SQLite: le connessioni ``sqlite3`` non sono condivisibili fra
thread e il costo di apertura su un file locale e' trascurabile.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterator, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel

from . import __version__, versions as versions_mod
from .config import META_LAST_SYNC
from .cpe import InvalidCPEError, parse_cpe23
from .db import DatabaseNotFoundError, connect, count_cves, get_meta
from .matcher import (
    AmbiguousProductError,
    MatchResult,
    SearchFilters,
    UnknownProductError,
    resolve_candidates,
    search,
    search_cves_for_cve_id,
)

__all__ = ["SearchResponse", "create_app"]


class SearchResponse(BaseModel):
    """Risposta dell'endpoint ``/search``."""

    target: str
    version: str
    count: int
    has_high_or_above: bool
    results: list[MatchResult]


def create_app(db_path: Path) -> FastAPI:
    """Costruisce l'applicazione FastAPI legata a un database specifico."""
    api = FastAPI(
        title="nvdlocal",
        version=__version__,
        description=(
            "Lookup offline delle CVE NIST NVD per software e versione. "
            "I dati provengono dal mirror SQLite locale."
        ),
    )

    def get_conn() -> Iterator[sqlite3.Connection]:
        try:
            conn = connect(db_path)
        except DatabaseNotFoundError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        try:
            yield conn
        finally:
            conn.close()

    @api.get("/health", summary="Stato del servizio e del database")
    def health(conn: sqlite3.Connection = Depends(get_conn)) -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "db_path": str(db_path),
            "cve_count": count_cves(conn),
            "last_sync": get_meta(conn, META_LAST_SYNC),
        }

    @api.get("/search", response_model=SearchResponse, summary="CVE per software e versione")
    def search_endpoint(
        version: str = Query(..., description="Versione del software, es. 2.4.52"),
        product: Optional[str] = Query(None, description="Prodotto o alias, es. httpd"),
        vendor: Optional[str] = Query(None, description="Vendor, per disambiguare"),
        cpe: Optional[str] = Query(None, description="CPE 2.3 completo, alternativo a product"),
        min_severity: Optional[str] = Query(None, description="LOW|MEDIUM|HIGH|CRITICAL"),
        min_score: Optional[float] = Query(None, ge=0, le=10),
        only_kev: bool = Query(False),
        min_epss: Optional[float] = Query(None, ge=0, le=1),
        include_all_versions: bool = Query(True),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> SearchResponse:
        if not product and not cpe:
            raise HTTPException(status_code=400, detail="serve 'product' oppure 'cpe'")
        filters = SearchFilters(
            min_severity=min_severity,
            min_score=min_score,
            only_kev=only_kev,
            min_epss=min_epss,
            include_all_versions=include_all_versions,
        )
        try:
            results = search(
                conn, version=version, product=product, vendor=vendor, cpe=cpe, filters=filters
            )
        except AmbiguousProductError as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": str(exc),
                    "candidates": [c.model_dump() for c in exc.candidates[:25]],
                },
            ) from exc
        except UnknownProductError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        target = product or (cpe or "")
        return SearchResponse(
            target=target,
            version=version,
            count=len(results),
            has_high_or_above=any(r.is_high_or_above for r in results),
            results=results,
        )

    @api.get("/resolve", summary="Candidati vendor:product per un termine")
    def resolve_endpoint(
        term: str = Query(..., description="Termine da risolvere, es. 'apache http'"),
        vendor: Optional[str] = Query(None),
        limit: int = Query(25, ge=1, le=200),
        conn: sqlite3.Connection = Depends(get_conn),
    ) -> dict[str, Any]:
        candidates = resolve_candidates(conn, term, vendor)
        return {
            "term": term,
            "count": len(candidates),
            "candidates": [c.model_dump() for c in candidates[:limit]],
        }

    @api.get("/cve/{cve_id}", summary="Dettaglio di una CVE")
    def cve_endpoint(
        cve_id: str, conn: sqlite3.Connection = Depends(get_conn)
    ) -> dict[str, Any]:
        detail = search_cves_for_cve_id(conn, cve_id)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"{cve_id} non presente nel database")
        detail["cve"].pop("raw_json", None)
        return detail

    @api.get("/cpe/parse", summary="Parsing di una stringa CPE 2.3")
    def parse_endpoint(cpe: str = Query(..., description="Stringa CPE 2.3")) -> dict[str, Any]:
        try:
            parsed = parse_cpe23(cpe)
        except InvalidCPEError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "part": parsed.part,
            "vendor": parsed.vendor,
            "product": parsed.product,
            "version": parsed.version,
            "update": parsed.update,
            "edition": parsed.edition,
            "language": parsed.language,
            "sw_edition": parsed.sw_edition,
            "target_sw": parsed.target_sw,
            "target_hw": parsed.target_hw,
            "other": parsed.other,
            "version_is_concrete": versions_mod.is_concrete(parsed.version),
        }

    return api
