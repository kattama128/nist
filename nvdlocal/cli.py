"""Interfaccia a riga di comando (typer) di nvdlocal."""

from __future__ import annotations

import csv
import sqlite3
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import __version__
from .config import (
    META_EPSS_SYNC,
    META_FULL_SYNC_DONE,
    META_FULL_SYNC_INDEX,
    META_KEV_SYNC,
    META_LAST_SYNC,
    get_api_key,
    get_logger,
    resolve_db_path,
    setup_logging,
)
from .cpe import InvalidCPEError, parse_cpe23
from .db import (
    DatabaseNotFoundError,
    connect,
    count_cves,
    database_size,
    get_meta,
    init_db,
)
from .enrich import EnrichError, sync_enrichment
from .matcher import (
    AmbiguousProductError,
    InventoryRow,
    SearchFilters,
    UnknownProductError,
    high_or_above,
    process_inventory,
    resolve_candidates,
    search,
    search_cves_for_cve_id,
)
from .output import (
    console,
    err_console,
    human_size,
    render_candidates,
    render_cve_detail,
    render_stats,
    write_batch_output,
    write_results,
)
from .sync import NVDClient, NVDError, sync_full, sync_incremental
from . import versions as versions_mod

LOG = get_logger()

app = typer.Typer(
    name="nvdlocal",
    help=(
        "Mirror locale del NIST NVD con lookup delle CVE per software e versione. "
        "Dopo la sincronizzazione iniziale funziona completamente offline."
    ),
    add_completion=False,
    no_args_is_help=True,
)

#: Exit code usato per gli errori operativi (DB assente, rete, input non valido).
EXIT_ERROR = 2


class Format(str, Enum):
    """Formati di output supportati da ``search``."""

    table = "table"
    json = "json"
    csv = "csv"


class Severity(str, Enum):
    """Severita' CVSS accettate da ``--min-severity``."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Context:
    """Stato condiviso fra il callback globale e i sottocomandi."""

    def __init__(self, db_path: Path, verbose: bool) -> None:
        self.db_path = db_path
        self.verbose = verbose


def _ctx(ctx: typer.Context) -> Context:
    return ctx.obj  # type: ignore[return-value]


def _open_db(ctx: typer.Context, create: bool = False) -> sqlite3.Connection:
    """Apre il database mostrando un errore leggibile se non esiste."""
    state = _ctx(ctx)
    try:
        conn = connect(state.db_path, create=create)
    except DatabaseNotFoundError as exc:
        err_console.print(f"[red]Errore:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    if create:
        init_db(conn)
    return conn


def _progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    db: Annotated[
        Optional[Path],
        typer.Option("--db", help="Percorso del database SQLite (default: NVDLOCAL_DB o ~/.local/share/nvdlocal/nvd.db)."),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Log di debug.")] = False,
    version: Annotated[
        bool, typer.Option("--version", help="Mostra la versione ed esce.")
    ] = False,
) -> None:
    """Configura path del database e logging per tutti i sottocomandi."""
    if version:
        console.print(f"nvdlocal {__version__}")
        raise typer.Exit()
    db_path = resolve_db_path(db)
    setup_logging(db_path, verbose=verbose)
    ctx.obj = Context(db_path=db_path, verbose=verbose)
    if ctx.invoked_subcommand is None:
        # markup=False: l'help e' gia' formattato da typer e contiene testo come
        # "[OPTIONS]" che rich interpreterebbe come tag di stile.
        console.print(ctx.get_help(), markup=False, highlight=False)
        # Stesso exit code di 'nvdlocal' senza argomenti: nessun comando eseguito.
        raise typer.Exit(EXIT_ERROR)


# --------------------------------------------------------------------------- #
# sync
# --------------------------------------------------------------------------- #
@app.command()
def sync(
    ctx: typer.Context,
    full: Annotated[bool, typer.Option("--full", help="Scarica l'intero catalogo CVE.")] = False,
    incremental: Annotated[
        bool, typer.Option("--incremental", help="Scarica solo le CVE modificate dall'ultima sync.")
    ] = False,
    enrich: Annotated[
        bool, typer.Option("--enrich", help="Aggiorna CISA KEV ed EPSS.")
    ] = False,
    resume: Annotated[
        bool, typer.Option("--resume", help="Riprende una sync completa interrotta.")
    ] = False,
    api_key: Annotated[
        Optional[str],
        typer.Option("--api-key", help="API key NVD (default: variabile NVD_API_KEY o .env)."),
    ] = None,
    max_pages: Annotated[
        Optional[int],
        typer.Option("--max-pages", help="Limita il numero di pagine scaricate (test/sync parziale)."),
    ] = None,
) -> None:
    """Sincronizza il database locale con NVD, CISA KEV ed EPSS."""
    if not (full or incremental or enrich):
        err_console.print(
            "[red]Errore:[/red] specifica almeno una fra --full, --incremental, --enrich."
        )
        raise typer.Exit(EXIT_ERROR)

    conn = _open_db(ctx, create=True)
    key = get_api_key(api_key)
    if (full or incremental) and not key:
        console.print(
            "[yellow]Nessuna API key NVD:[/yellow] verra' usata una pausa di 6s fra le "
            "richieste. Richiedine una gratuita su "
            "https://nvd.nist.gov/developers/request-an-api-key e impostala in NVD_API_KEY."
        )

    try:
        if full:
            with NVDClient(api_key=key) as client, _progress() as progress:
                stats = sync_full(
                    conn, client, resume=resume, max_pages=max_pages, progress=progress
                )
            console.print(
                f"[green]Sync completa:[/green] {stats.cves:,} CVE in {stats.pages} pagine"
                + ("" if stats.completed else " [yellow](interrotta, usa --resume)[/yellow]")
            )

        enrich_requested = enrich
        if incremental:
            with NVDClient(api_key=key) as client, _progress() as progress:
                stats = sync_incremental(conn, client, progress=progress)
            console.print(f"[green]Sync incrementale:[/green] {stats.cves:,} CVE aggiornate")
            # Dopo una incrementale l'arricchimento e' automatico.
            enrich = True

        if enrich:
            kev_count, epss_count = sync_enrichment(conn)
            console.print(
                f"[green]Arricchimento:[/green] {kev_count:,} CVE in KEV, "
                f"{epss_count:,} score EPSS"
            )
            if enrich_requested and not kev_count and not epss_count:
                err_console.print(
                    "[red]Errore:[/red] nessuna delle due sorgenti di arricchimento "
                    "e' stata raggiunta (vedi i messaggi sopra)."
                )
                raise typer.Exit(EXIT_ERROR)
    except NVDError as exc:
        err_console.print(f"[red]Errore di sincronizzazione:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    except EnrichError as exc:
        err_console.print(f"[red]Errore di arricchimento:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    except KeyboardInterrupt:  # pragma: no cover - interazione utente
        err_console.print(
            "[yellow]Interrotto.[/yellow] Riprendi con 'nvdlocal sync --full --resume'."
        )
        raise typer.Exit(130)
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# search
# --------------------------------------------------------------------------- #
@app.command("search")
def search_cmd(
    ctx: typer.Context,
    product: Annotated[
        Optional[str], typer.Option("--product", "-p", help="Nome del prodotto o alias (es. httpd).")
    ] = None,
    version: Annotated[
        Optional[str], typer.Option("--version", "-V", help="Versione del software (es. 2.4.52).")
    ] = None,
    vendor: Annotated[
        Optional[str], typer.Option("--vendor", help="Vendor, per disambiguare (es. apache).")
    ] = None,
    cpe: Annotated[
        Optional[str], typer.Option("--cpe", help="CPE 2.3 completo, in alternativa a --product.")
    ] = None,
    min_severity: Annotated[
        Optional[Severity],
        typer.Option("--min-severity", case_sensitive=False, help="Severita' minima."),
    ] = None,
    min_score: Annotated[
        Optional[float], typer.Option("--min-score", help="Score CVSS minimo.")
    ] = None,
    only_kev: Annotated[
        bool, typer.Option("--only-kev", help="Solo CVE nel catalogo CISA KEV.")
    ] = False,
    min_epss: Annotated[
        Optional[float], typer.Option("--min-epss", help="Score EPSS minimo (0.0-1.0).")
    ] = None,
    include_all_versions: Annotated[
        bool,
        typer.Option(
            "--include-all-versions/--no-include-all-versions",
            help="Include i match su CPE senza versione (marcati all_versions).",
        ),
    ] = True,
    output_format: Annotated[
        Format,
        typer.Option("--format", "-f", case_sensitive=False, help="Formato di output."),
    ] = Format.table,
    output: Annotated[
        Optional[Path], typer.Option("--output", "-o", help="Scrive il risultato su file.")
    ] = None,
) -> None:
    """Cerca le CVE che affliggono un software in una versione specifica.

    Exit code: 0 se non trova nulla o solo CVE sotto HIGH, 1 se trova almeno
    una CVE con severita' HIGH o CRITICAL (utile in pipeline).
    """
    if not product and not cpe:
        err_console.print("[red]Errore:[/red] serve --product oppure --cpe.")
        raise typer.Exit(EXIT_ERROR)

    target_version = version
    label = product or ""
    if cpe:
        try:
            parsed = parse_cpe23(cpe)
        except InvalidCPEError as exc:
            err_console.print(f"[red]Errore:[/red] {exc}")
            raise typer.Exit(EXIT_ERROR) from exc
        label = parsed.vendor_product
        if target_version is None and versions_mod.is_concrete(parsed.version):
            target_version = parsed.version

    if not target_version:
        err_console.print(
            "[red]Errore:[/red] serve --version (oppure un CPE con la versione valorizzata)."
        )
        raise typer.Exit(EXIT_ERROR)

    conn = _open_db(ctx)
    try:
        results = search(
            conn,
            version=target_version,
            product=product,
            vendor=vendor,
            cpe=cpe,
            filters=SearchFilters(
                min_severity=min_severity.value if min_severity else None,
                min_score=min_score,
                only_kev=only_kev,
                min_epss=min_epss,
                include_all_versions=include_all_versions,
            ),
        )
    except AmbiguousProductError as exc:
        err_console.print(f"[yellow]{exc}[/yellow]")
        render_candidates(exc.candidates, exc.term, out=err_console)
        raise typer.Exit(EXIT_ERROR) from exc
    except UnknownProductError as exc:
        err_console.print(f"[yellow]{exc}[/yellow]")
        raise typer.Exit(EXIT_ERROR) from exc
    except ValueError as exc:
        err_console.print(f"[red]Errore:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    finally:
        conn.close()

    write_results(results, output_format.value, f"{label} {target_version}", output)
    raise typer.Exit(1 if high_or_above(results) else 0)


# --------------------------------------------------------------------------- #
# resolve
# --------------------------------------------------------------------------- #
@app.command()
def resolve(
    ctx: typer.Context,
    term: Annotated[str, typer.Argument(help="Termine da risolvere, es. 'apache http'.")],
    vendor: Annotated[
        Optional[str], typer.Option("--vendor", help="Restringe la ricerca a un vendor.")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", help="Numero massimo di candidati.")] = 25,
) -> None:
    """Trova il ``vendor:product`` CPE corrispondente a un nome commerciale."""
    conn = _open_db(ctx)
    try:
        candidates = resolve_candidates(conn, term, vendor)
    finally:
        conn.close()
    render_candidates(candidates[:limit], term)
    if not candidates:
        raise typer.Exit(EXIT_ERROR)


# --------------------------------------------------------------------------- #
# batch
# --------------------------------------------------------------------------- #
def read_inventory(path: Path) -> list[InventoryRow]:
    """Legge un inventario CSV con colonne ``host,port,vendor,product,version``.

    :raises ValueError: se mancano le colonne obbligatorie ``product`` e ``version``.
    """
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"{path} e' vuoto")
        columns = {(name or "").strip().lower() for name in reader.fieldnames}
        missing = {"product", "version"} - columns
        if missing:
            raise ValueError(
                f"{path}: colonne mancanti {sorted(missing)}; "
                "attese host,port,vendor,product,version"
            )
        rows: list[InventoryRow] = []
        for record in reader:
            clean = {
                (k or "").strip().lower(): (v or "").strip()
                for k, v in record.items()
                if k
            }
            rows.append(
                InventoryRow(
                    host=clean.get("host", ""),
                    port=clean.get("port", ""),
                    vendor=clean.get("vendor") or None,
                    product=clean.get("product", ""),
                    version=clean.get("version", ""),
                )
            )
    return rows


@app.command()
def batch(
    ctx: typer.Context,
    input_file: Annotated[
        Path, typer.Option("--input", "-i", help="Inventario CSV: host,port,vendor,product,version.")
    ],
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Report .xlsx (o .csv) da produrre.")
    ],
    min_severity: Annotated[
        Optional[Severity],
        typer.Option("--min-severity", case_sensitive=False, help="Severita' minima."),
    ] = None,
    min_score: Annotated[
        Optional[float], typer.Option("--min-score", help="Score CVSS minimo.")
    ] = None,
    only_kev: Annotated[
        bool, typer.Option("--only-kev", help="Solo CVE nel catalogo CISA KEV.")
    ] = False,
    min_epss: Annotated[
        Optional[float], typer.Option("--min-epss", help="Score EPSS minimo.")
    ] = None,
    include_all_versions: Annotated[
        bool,
        typer.Option(
            "--include-all-versions/--no-include-all-versions",
            help="Include i match su CPE senza versione.",
        ),
    ] = True,
) -> None:
    """Elabora un inventario di host e produce un report con una riga per (host, CVE)."""
    if not input_file.is_file():
        err_console.print(f"[red]Errore:[/red] inventario non trovato: {input_file}")
        raise typer.Exit(EXIT_ERROR)
    try:
        rows = read_inventory(input_file)
    except ValueError as exc:
        err_console.print(f"[red]Errore:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    conn = _open_db(ctx)
    filters = SearchFilters(
        min_severity=min_severity.value if min_severity else None,
        min_score=min_score,
        only_kev=only_kev,
        min_epss=min_epss,
        include_all_versions=include_all_versions,
    )
    try:
        with _progress() as progress:
            task = progress.add_task("[cyan]analisi inventario", total=len(rows))
            findings: list[Any] = []
            unresolved: list[Any] = []
            for row in rows:
                row_findings, row_unresolved = process_inventory(conn, [row], filters)
                findings.extend(row_findings)
                unresolved.extend(row_unresolved)
                progress.advance(task)
    finally:
        conn.close()

    try:
        written = write_batch_output(findings, unresolved, output)
    except RuntimeError as exc:
        err_console.print(f"[red]Errore:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    console.print(
        f"[green]Batch completato:[/green] {len(rows)} righe di inventario, "
        f"{len(findings)} coppie (host, CVE), {len(unresolved)} righe non risolte"
    )
    for path in written:
        console.print(f"  scritto {path}")

    if any(f.result.is_high_or_above for f in findings):
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
# show
# --------------------------------------------------------------------------- #
@app.command()
def show(
    ctx: typer.Context,
    cve_id: Annotated[str, typer.Argument(help="Identificativo CVE, es. CVE-2021-41773.")],
) -> None:
    """Mostra il dettaglio completo di una CVE presente nel database locale."""
    conn = _open_db(ctx)
    try:
        detail = search_cves_for_cve_id(conn, cve_id)
    finally:
        conn.close()
    if detail is None:
        err_console.print(
            f"[yellow]{cve_id.upper()} non presente nel database locale.[/yellow] "
            "Potrebbe servire una 'nvdlocal sync --incremental'."
        )
        raise typer.Exit(EXIT_ERROR)
    render_cve_detail(detail)


# --------------------------------------------------------------------------- #
# stats
# --------------------------------------------------------------------------- #
@app.command()
def stats(ctx: typer.Context) -> None:
    """Statistiche del database locale: CVE, ultima sync, dimensione, top vendor."""
    state = _ctx(ctx)
    conn = _open_db(ctx)
    try:
        severity_rows = conn.execute(
            "SELECT COALESCE(cvss_severity, 'N/D') AS severity, COUNT(*) AS n "
            "FROM cve GROUP BY severity ORDER BY n DESC"
        ).fetchall()
        vendor_rows = conn.execute(
            "SELECT vendor, COUNT(DISTINCT cve_id) AS n FROM cpe_match "
            "WHERE vendor IS NOT NULL AND vendor != '*' "
            "GROUP BY vendor ORDER BY n DESC LIMIT 10"
        ).fetchall()
        payload = {
            "db_path": state.db_path,
            "db_size_human": human_size(database_size(state.db_path)),
            "cve_count": count_cves(conn),
            "cpe_match_count": int(
                conn.execute("SELECT COUNT(*) AS n FROM cpe_match").fetchone()["n"]
            ),
            "kev_count": int(conn.execute("SELECT COUNT(*) AS n FROM kev").fetchone()["n"]),
            "epss_count": int(conn.execute("SELECT COUNT(*) AS n FROM epss").fetchone()["n"]),
            "last_sync": get_meta(conn, META_LAST_SYNC),
            "full_sync_completed": get_meta(conn, META_FULL_SYNC_DONE),
            "resume_index": get_meta(conn, META_FULL_SYNC_INDEX),
            "kev_sync": get_meta(conn, META_KEV_SYNC),
            "epss_sync": get_meta(conn, META_EPSS_SYNC),
            "severity_breakdown": [(r["severity"], r["n"]) for r in severity_rows],
            "top_vendors": [(r["vendor"], r["n"]) for r in vendor_rows],
        }
    finally:
        conn.close()
    render_stats(payload)


# --------------------------------------------------------------------------- #
# serve
# --------------------------------------------------------------------------- #
@app.command()
def serve(
    ctx: typer.Context,
    host: Annotated[str, typer.Option("--host", help="Indirizzo di ascolto.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Porta di ascolto.")] = 8000,
) -> None:
    """Espone la ricerca via HTTP: ``GET /search?product=&version=&vendor=``."""
    state = _ctx(ctx)
    if not state.db_path.exists():
        err_console.print(
            f"[red]Errore:[/red] database non trovato in {state.db_path}. "
            "Esegui prima 'nvdlocal sync --full'."
        )
        raise typer.Exit(EXIT_ERROR)
    try:
        import uvicorn

        from .api import create_app
    except ImportError as exc:
        err_console.print(
            "[red]Errore:[/red] per 'serve' servono fastapi e uvicorn "
            "(pip install fastapi uvicorn)."
        )
        raise typer.Exit(EXIT_ERROR) from exc

    console.print(f"[green]nvdlocal API[/green] su http://{host}:{port} (db: {state.db_path})")
    uvicorn.run(create_app(state.db_path), host=host, port=port, log_level="info")


def run() -> None:  # pragma: no cover - entry point
    """Entry point della console script ``nvdlocal``."""
    app()


if __name__ == "__main__":  # pragma: no cover
    run()
