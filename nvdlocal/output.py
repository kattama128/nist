"""Rendering dei risultati: tabella (rich), JSON e CSV.

Questo e' l'unico modulo che scrive sullo standard output per l'utente: la
diagnostica passa da ``logging``, qui si usa solo ``rich``.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .matcher import MatchResult, MatchType, ProductCandidate

__all__ = [
    "CSV_COLUMNS",
    "FORMATS",
    "console",
    "render_candidates",
    "render_cve_detail",
    "render_results",
    "render_stats",
    "results_to_csv",
    "results_to_json",
    "write_results",
]

FORMATS = ("table", "json", "csv")

console = Console()
err_console = Console(stderr=True)

#: Colonne del formato CSV (e dell'export batch).
CSV_COLUMNS = (
    "cve_id",
    "cvss_score",
    "cvss_severity",
    "cvss_version",
    "cvss_vector",
    "cwe",
    "kev",
    "kev_date_added",
    "kev_ransomware",
    "kev_due_date",
    "epss_score",
    "epss_percentile",
    "published",
    "last_modified",
    "vuln_status",
    "match_type",
    "version_match",
    "criteria",
    "version_range",
    "conditions",
    "description",
)

_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "NONE": "dim",
}

_MATCH_STYLE = {
    MatchType.EXACT: "bold green",
    MatchType.RANGE: "cyan",
    MatchType.ALL_VERSIONS: "yellow",
    MatchType.CONDITIONAL: "magenta",
}


def _severity_text(result: MatchResult) -> Text:
    severity = (result.cvss_severity or "N/D").upper()
    return Text(severity, style=_SEVERITY_STYLE.get(severity, "dim"))


def _short(text: str, width: int = 90) -> str:
    collapsed = " ".join((text or "").split())
    return collapsed if len(collapsed) <= width else collapsed[: width - 1] + "…"


def render_results(
    results: Sequence[MatchResult],
    target: str,
    out: Console | None = None,
) -> None:
    """Stampa i risultati come tabella rich, evidenziando in rosso le CVE in KEV."""
    out = out or console
    if not results:
        out.print(f"[green]Nessuna CVE trovata per[/green] [bold]{target}[/bold]")
        return

    table = Table(
        title=f"CVE applicabili a {target} ({len(results)})",
        header_style="bold white on blue",
        expand=False,
    )
    # min_width protegge le colonne identificative quando il terminale e' stretto:
    # rich restringe prima la descrizione, che e' l'unica davvero elastica.
    table.add_column("CVE", no_wrap=True, min_width=14)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Severita'", no_wrap=True, min_width=8)
    table.add_column("KEV", justify="center", no_wrap=True)
    table.add_column("EPSS", justify="right", no_wrap=True)
    table.add_column("Match", no_wrap=True, min_width=11)
    table.add_column("Versioni", no_wrap=True, min_width=12)
    table.add_column("Pubblicata", no_wrap=True, min_width=10)
    table.add_column("CWE", no_wrap=True)
    table.add_column("Descrizione", overflow="ellipsis", max_width=60)

    for result in results:
        kev_flag = Text("SI", style="bold white on red") if result.kev else Text("-", style="dim")
        cve_style = "bold red" if result.kev else ""
        table.add_row(
            Text(result.cve_id, style=cve_style),
            f"{result.cvss_score:.1f}" if result.cvss_score is not None else "-",
            _severity_text(result),
            kev_flag,
            f"{result.epss_score:.4f}" if result.epss_score is not None else "-",
            Text(result.match_type.value, style=_MATCH_STYLE.get(result.match_type, "")),
            result.version_range,
            (result.published or "")[:10],
            _short(result.cwe, 22) or "-",
            _short(result.description, 220),
        )

    out.print(table)

    conditionals = [r for r in results if r.match_type is MatchType.CONDITIONAL]
    if conditionals:
        body = Text()
        for result in conditionals:
            body.append(f"{result.cve_id}", style="bold magenta")
            body.append(f"  {result.criteria}\n", style="dim")
            for condition in result.conditions:
                body.append(f"    + richiede anche: {condition}\n", style="dim")
        out.print(
            Panel(
                body,
                title="Match condizionali (configurazione AND: serve un altro componente)",
                border_style="magenta",
            )
        )

    all_versions = sum(1 for r in results if r.match_type is MatchType.ALL_VERSIONS)
    if all_versions:
        out.print(
            f"[yellow]{all_versions}[/yellow] match di tipo [yellow]all_versions[/yellow]: "
            "il CPE non indica alcuna versione, verificare manualmente."
        )


def results_to_json(results: Sequence[MatchResult], target: str = "") -> str:
    """Serializza i risultati in JSON indentato."""
    payload = {
        "target": target,
        "count": len(results),
        "results": [r.model_dump(mode="json") for r in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _result_row(result: MatchResult) -> dict[str, Any]:
    data = result.model_dump(mode="json")
    data["kev"] = "yes" if result.kev else "no"
    data["conditions"] = " | ".join(result.conditions)
    data["description"] = " ".join((result.description or "").split())
    return {column: data.get(column, "") for column in CSV_COLUMNS}


def results_to_csv(results: Sequence[MatchResult]) -> str:
    """Serializza i risultati in CSV con intestazione."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS), lineterminator="\n")
    writer.writeheader()
    for result in results:
        writer.writerow(_result_row(result))
    return buffer.getvalue()


def write_results(
    results: Sequence[MatchResult],
    fmt: str,
    target: str,
    output: Path | None = None,
) -> None:
    """Scrive i risultati nel formato richiesto, su file o su stdout."""
    if fmt == "table" and output is None:
        render_results(results, target)
        return

    if fmt == "json":
        payload = results_to_json(results, target)
    elif fmt == "csv":
        payload = results_to_csv(results)
    else:  # table su file: si esporta la versione testuale
        buffer = Console(file=io.StringIO(), width=200)
        render_results(results, target, out=buffer)
        payload = buffer.file.getvalue()  # type: ignore[union-attr]

    if output is None:
        # soft_wrap evita che rich mandi a capo JSON e CSV sulla larghezza del terminale.
        console.print(payload, markup=False, highlight=False, soft_wrap=True)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
        console.print(f"[green]Scritti {len(results)} risultati in[/green] {output}")


def render_candidates(
    candidates: Sequence[ProductCandidate], term: str, out: Console | None = None
) -> None:
    """Stampa i candidati ``vendor:product`` con il conteggio delle CVE."""
    out = out or console
    if not candidates:
        out.print(f"[yellow]Nessun prodotto trovato per[/yellow] [bold]{term}[/bold]")
        return
    table = Table(title=f"Candidati per '{term}'", header_style="bold white on blue")
    table.add_column("Vendor", no_wrap=True)
    table.add_column("Product", no_wrap=True)
    table.add_column("CPE", no_wrap=True)
    table.add_column("CVE", justify="right", no_wrap=True)
    for candidate in candidates:
        table.add_row(
            candidate.vendor,
            candidate.product,
            f"cpe:2.3:a:{candidate.vendor}:{candidate.product}:*:*:*:*:*:*:*:*",
            f"{candidate.cve_count:,}",
        )
    out.print(table)


def render_cve_detail(detail: dict[str, Any], out: Console | None = None) -> None:
    """Stampa il dettaglio completo di una CVE (comando ``show``)."""
    out = out or console
    cve = detail["cve"]
    severity = (cve.get("cvss_severity") or "N/D").upper()

    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold cyan", no_wrap=True)
    header.add_column(overflow="fold")
    header.add_row("Pubblicata", str(cve.get("published") or "-"))
    header.add_row("Ultima modifica", str(cve.get("last_modified") or "-"))
    header.add_row("Stato", str(cve.get("vuln_status") or "-"))
    header.add_row(
        "CVSS",
        f"{cve.get('cvss_score')} ({severity}) v{cve.get('cvss_version') or '?'}",
    )
    header.add_row("Vettore", str(cve.get("cvss_vector") or "-"))
    header.add_row("CWE", str(cve.get("cwe") or "-"))
    if cve.get("kev_date_added"):
        header.add_row(
            "CISA KEV",
            f"[bold red]sfruttamento noto[/bold red] dal {cve['kev_date_added']}"
            f" - ransomware: {cve.get('kev_ransomware') or 'n/d'}"
            f" - scadenza remediation: {cve.get('kev_due_date') or 'n/d'}",
        )
    if cve.get("epss_score") is not None:
        header.add_row(
            "EPSS",
            f"{cve['epss_score']:.5f} (percentile {cve.get('epss_percentile') or 0:.3f})",
        )

    out.print(
        Panel(
            header,
            title=f"[bold]{cve['cve_id']}[/bold]",
            border_style=_SEVERITY_STYLE.get(severity, "white"),
        )
    )
    out.print(Panel(str(cve.get("description") or ""), title="Descrizione", border_style="dim"))

    matches = detail.get("cpe_match") or []
    if matches:
        table = Table(title=f"Configurazioni ({len(matches)} CPE)", header_style="bold white on blue")
        table.add_column("Cfg", justify="right", no_wrap=True)
        table.add_column("Nodo", justify="right", no_wrap=True)
        table.add_column("Op", no_wrap=True)
        table.add_column("Vuln", justify="center", no_wrap=True)
        table.add_column("CPE", overflow="fold")
        table.add_column("Range versioni", overflow="fold")
        for match in matches:
            bounds = []
            for field, symbol in (
                ("version_start_including", ">="),
                ("version_start_excluding", ">"),
                ("version_end_including", "<="),
                ("version_end_excluding", "<"),
            ):
                if match.get(field):
                    bounds.append(f"{symbol} {match[field]}")
            table.add_row(
                str(match.get("config_index")),
                str(match.get("node_index")),
                f"{match.get('config_operator') or '-'}/{match.get('node_operator') or '-'}",
                "si" if match.get("vulnerable") else "no",
                str(match.get("criteria")),
                ", ".join(bounds) or "-",
            )
        out.print(table)

    try:
        references = json.loads(cve.get("references_json") or "[]")
    except json.JSONDecodeError:
        references = []
    if references:
        ref_table = Table(title="Riferimenti", header_style="bold white on blue")
        ref_table.add_column("URL", overflow="fold")
        ref_table.add_column("Tag", overflow="fold")
        for ref in references[:25]:
            ref_table.add_row(str(ref.get("url", "")), ", ".join(ref.get("tags") or []))
        out.print(ref_table)


def render_stats(stats: dict[str, Any], out: Console | None = None) -> None:
    """Stampa le statistiche del database locale (comando ``stats``)."""
    out = out or console
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()
    grid.add_row("Database", str(stats["db_path"]))
    grid.add_row("Dimensione", stats["db_size_human"])
    grid.add_row("CVE totali", f"{stats['cve_count']:,}")
    grid.add_row("Righe cpe_match", f"{stats['cpe_match_count']:,}")
    grid.add_row("CVE in CISA KEV", f"{stats['kev_count']:,}")
    grid.add_row("Score EPSS", f"{stats['epss_count']:,}")
    grid.add_row("Ultima sync", str(stats["last_sync"] or "mai"))
    grid.add_row("Sync completa", str(stats["full_sync_completed"] or "mai completata"))
    if stats.get("resume_index"):
        grid.add_row("Checkpoint resume", f"startIndex={stats['resume_index']}")
    out.print(Panel(grid, title="nvdlocal - stato del database", border_style="cyan"))

    if stats.get("severity_breakdown"):
        table = Table(title="CVE per severita'", header_style="bold white on blue")
        table.add_column("Severita'", no_wrap=True)
        table.add_column("CVE", justify="right")
        for severity, count in stats["severity_breakdown"]:
            table.add_row(
                Text(severity or "N/D", style=_SEVERITY_STYLE.get(severity or "", "dim")),
                f"{count:,}",
            )
        out.print(table)

    if stats.get("top_vendors"):
        table = Table(title="Top vendor per numero di CVE", header_style="bold white on blue")
        table.add_column("#", justify="right", no_wrap=True)
        table.add_column("Vendor", no_wrap=True)
        table.add_column("CVE", justify="right")
        for position, (vendor, count) in enumerate(stats["top_vendors"], start=1):
            table.add_row(str(position), vendor, f"{count:,}")
        out.print(table)


#: Colonne del report batch (una riga per coppia host/CVE).
BATCH_COLUMNS = (
    "host",
    "port",
    "software",
    "versione",
    "cve",
    "score",
    "severity",
    "kev",
    "epss",
    "match_type",
    "range_versioni",
    "cpe",
    "descrizione",
)

BATCH_UNRESOLVED_COLUMNS = (
    "host",
    "port",
    "vendor",
    "product",
    "version",
    "motivo",
    "candidati",
)


def _batch_rows(findings: Sequence[Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for finding in findings:
        result = finding.result
        rows.append(
            [
                finding.host,
                finding.port,
                finding.software,
                finding.version,
                result.cve_id,
                result.cvss_score,
                result.cvss_severity,
                "SI" if result.kev else "",
                result.epss_score,
                result.match_type.value,
                result.version_range,
                result.criteria,
                " ".join((result.description or "").split()),
            ]
        )
    return rows


def _unresolved_rows(unresolved: Sequence[Any]) -> list[list[Any]]:
    return [
        [
            item.host,
            item.port,
            item.vendor,
            item.product,
            item.version,
            item.reason,
            ", ".join(item.candidates),
        ]
        for item in unresolved
    ]


def write_batch_output(
    findings: Sequence[Any],
    unresolved: Sequence[Any],
    output: Path,
) -> list[Path]:
    """Scrive il report batch.

    Con estensione ``.xlsx`` produce un unico workbook con i fogli
    ``risultati`` e ``non_risolti``; con qualsiasi altra estensione produce due
    CSV affiancati (``<nome>.csv`` e ``<nome>_non_risolti.csv``).

    :return: elenco dei file scritti.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.suffix.lower() in (".xlsx", ".xlsm"):
        return [_write_xlsx(findings, unresolved, output)]
    return _write_batch_csv(findings, unresolved, output)


def _write_xlsx(
    findings: Sequence[Any], unresolved: Sequence[Any], output: Path
) -> Path:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError as exc:  # pragma: no cover - dipende dall'ambiente
        raise RuntimeError(
            "per l'output .xlsx serve openpyxl: installalo con 'pip install openpyxl' "
            "oppure usa un output .csv"
        ) from exc

    workbook = Workbook()
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="1F4E79")
    kev_fill = PatternFill("solid", fgColor="FFC7CE")

    sheet = workbook.active
    sheet.title = "risultati"
    sheet.append(list(BATCH_COLUMNS))
    kev_index = BATCH_COLUMNS.index("kev")
    for row in _batch_rows(findings):
        sheet.append(row)
        if row[kev_index] == "SI":
            for cell in sheet[sheet.max_row]:
                cell.fill = kev_fill

    unresolved_sheet = workbook.create_sheet("non_risolti")
    unresolved_sheet.append(list(BATCH_UNRESOLVED_COLUMNS))
    for row in _unresolved_rows(unresolved):
        unresolved_sheet.append(row)

    widths = {
        "risultati": (18, 8, 26, 14, 18, 8, 10, 6, 10, 14, 24, 46, 80),
        "non_risolti": (18, 8, 18, 24, 14, 40, 40),
    }
    for name, sizes in widths.items():
        target = workbook[name]
        for index, width in enumerate(sizes, start=1):
            target.column_dimensions[get_column_letter(index)].width = width
        for cell in target[1]:
            cell.font = header_font
            cell.fill = header_fill
        target.freeze_panes = "A2"

    workbook.save(output)
    return output


def _write_batch_csv(
    findings: Sequence[Any], unresolved: Sequence[Any], output: Path
) -> list[Path]:
    main = output if output.suffix else output.with_suffix(".csv")
    other = main.with_name(f"{main.stem}_non_risolti{main.suffix}")

    with main.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(BATCH_COLUMNS)
        writer.writerows(_batch_rows(findings))

    with other.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(BATCH_UNRESOLVED_COLUMNS)
        writer.writerows(_unresolved_rows(unresolved))

    return [main, other]


def human_size(num_bytes: int) -> str:
    """Formatta una dimensione in byte in forma leggibile."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"  # pragma: no cover
