"""Configurazione globale: percorsi, API key, costanti di rete e logging.

Nessun segreto e' hardcoded: la API key NVD viene letta da ``NVD_API_KEY``
(variabile d'ambiente o file ``.env`` nella working directory).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

# --------------------------------------------------------------------------- #
# Endpoint remoti
# --------------------------------------------------------------------------- #
NVD_CVE_API: Final[str] = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API: Final[str] = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
KEV_URL: Final[str] = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
EPSS_URL: Final[str] = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# --------------------------------------------------------------------------- #
# Parametri di paginazione / rate limiting NVD
# --------------------------------------------------------------------------- #
#: Massimo consentito dall'API NVD 2.0 per ``resultsPerPage``.
MAX_RESULTS_PER_PAGE: Final[int] = 2000
#: Finestra massima ammessa per lastModStartDate/lastModEndDate.
MAX_WINDOW_DAYS: Final[int] = 120
#: Pausa fra richieste con API key (limite reale: 50 req / 30s).
DELAY_WITH_KEY: Final[float] = 0.8
#: Pausa fra richieste senza API key (limite reale: 5 req / 30s).
DELAY_WITHOUT_KEY: Final[float] = 6.0

MAX_RETRIES: Final[int] = 5
BACKOFF_MIN: Final[float] = 10.0
BACKOFF_MAX: Final[float] = 120.0
#: Status HTTP che meritano un retry: NVD e' notoriamente instabile.
RETRY_STATUS: Final[frozenset[int]] = frozenset({403, 429, 500, 502, 503, 504})
HTTP_TIMEOUT: Final[float] = 60.0

#: Formato data accettato da NVD 2.0 (ISO-8601 con millisecondi).
NVD_DATE_FMT: Final[str] = "%Y-%m-%dT%H:%M:%S.000"

# --------------------------------------------------------------------------- #
# Chiavi della tabella meta
# --------------------------------------------------------------------------- #
META_SCHEMA_VERSION: Final[str] = "schema_version"
META_LAST_SYNC: Final[str] = "last_sync"
META_FULL_SYNC_INDEX: Final[str] = "full_sync_start_index"
META_FULL_SYNC_TOTAL: Final[str] = "full_sync_total"
META_FULL_SYNC_DONE: Final[str] = "full_sync_completed_at"
META_KEV_SYNC: Final[str] = "kev_last_sync"
META_EPSS_SYNC: Final[str] = "epss_last_sync"

LOGGER_NAME: Final[str] = "nvdlocal"

_ENV_LOADED = False


def load_env(explicit: Path | None = None) -> None:
    """Carica un file ``.env`` (se presente) senza sovrascrivere l'ambiente reale.

    Usa ``python-dotenv`` se installato, altrimenti un parser minimale.
    Idempotente: chiamate successive sono no-op.
    """
    global _ENV_LOADED
    if _ENV_LOADED and explicit is None:
        return
    _ENV_LOADED = True

    candidate = explicit or Path.cwd() / ".env"
    if not candidate.is_file():
        return
    try:  # pragma: no cover - dipende dall'ambiente
        from dotenv import load_dotenv

        load_dotenv(candidate, override=False)
        return
    except ImportError:  # pragma: no cover - fallback
        pass

    for raw in candidate.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def default_db_path() -> Path:
    """Percorso di default del database, sovrascrivibile con ``NVDLOCAL_DB``."""
    load_env()
    env = os.environ.get("NVDLOCAL_DB")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".local" / "share"
    return root / "nvdlocal" / "nvd.db"


def resolve_db_path(explicit: str | Path | None = None) -> Path:
    """Risolve il path del DB dando precedenza all'opzione esplicita ``--db``."""
    if explicit:
        return Path(explicit).expanduser()
    return default_db_path()


def get_api_key(explicit: str | None = None) -> str | None:
    """Restituisce la API key NVD: argomento CLI, poi ``NVD_API_KEY``, poi ``None``."""
    if explicit:
        return explicit
    load_env()
    key = os.environ.get("NVD_API_KEY", "").strip()
    return key or None


@dataclass(frozen=True)
class Settings:
    """Impostazioni effettive di una singola invocazione della CLI."""

    db_path: Path
    api_key: str | None = None

    @property
    def request_delay(self) -> float:
        """Pausa conservativa fra due richieste consecutive all'API NVD."""
        return DELAY_WITH_KEY if self.api_key else DELAY_WITHOUT_KEY


def log_file_path(db_path: Path) -> Path:
    """File di log, accanto al database."""
    return db_path.parent / "nvdlocal.log"


def setup_logging(db_path: Path, verbose: bool = False) -> logging.Logger:
    """Configura il logger applicativo su file + stdout (via rich se disponibile).

    Il layer di output utente resta separato: qui passa solo la diagnostica.
    """
    logger = logging.getLogger(LOGGER_NAME)
    if logger.handlers:
        logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    try:
        from rich.logging import RichHandler

        console_handler: logging.Handler = RichHandler(
            rich_tracebacks=False, show_path=False, show_time=False, markup=False
        )
        console_handler.setFormatter(logging.Formatter("%(message)s"))
    except ImportError:  # pragma: no cover - fallback
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(console_handler)

    try:
        path = log_file_path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )
        logger.addHandler(file_handler)
    except OSError:  # pragma: no cover - filesystem read-only
        logger.debug("impossibile aprire il file di log", exc_info=True)

    return logger


def get_logger() -> logging.Logger:
    """Logger applicativo (senza riconfigurarlo)."""
    return logging.getLogger(LOGGER_NAME)
