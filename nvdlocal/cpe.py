"""Parsing di CPE 2.3 (formatted string binding) e normalizzazione dei nomi.

La stringa CPE ha la forma::

    cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

I componenti possono contenere due punti *escapati* con backslash
(``cpe:2.3:a:apache:http_server:2.4.49\\:beta:*:...``), quindi un semplice
``split(":")`` produce risultati sbagliati: qui lo split e' consapevole
dell'escaping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Iterable, Mapping

__all__ = [
    "ALIASES",
    "CPE23",
    "CPE_PREFIX",
    "InvalidCPEError",
    "expand_alias",
    "normalize_name",
    "parse_cpe23",
    "split_components",
    "unquote",
]

CPE_PREFIX: Final[str] = "cpe:2.3:"

#: Ordine dei campi dopo il prefisso ``cpe:2.3:``.
_FIELDS: Final[tuple[str, ...]] = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)

_NORMALIZE_RE: Final[re.Pattern[str]] = re.compile(r"[\s\-]+")
_COLLAPSE_RE: Final[re.Pattern[str]] = re.compile(r"_{2,}")


class InvalidCPEError(ValueError):
    """La stringa non e' un CPE 2.3 valido."""


# Il parser CPE sta sul percorso caldo della sync (milioni di cpeMatch), quindi
# usa una dataclass slotted invece di un modello pydantic: i modelli validati
# con pydantic sono usati nel matcher e nella API, dove il volume e' basso.
@dataclass(frozen=True, slots=True)
class CPE23:
    """Un CPE 2.3 scomposto nei suoi undici attributi (gia' de-escapati)."""

    part: str = "*"
    vendor: str = "*"
    product: str = "*"
    version: str = "*"
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"

    @property
    def vendor_product(self) -> str:
        """Chiave ``vendor:product`` usata per identificare un software."""
        return f"{self.vendor}:{self.product}"

    def to_string(self) -> str:
        """Ricostruisce la stringa CPE 2.3 (senza reintrodurre l'escaping)."""
        return CPE_PREFIX + ":".join(getattr(self, f) for f in _FIELDS)


def split_components(cpe: str) -> list[str]:
    """Divide una stringa CPE sui due punti non escapati.

    >>> split_components("cpe:2.3:a:apache:http_server:2.4.49\\\\:beta:*")
    ['cpe', '2.3', 'a', 'apache', 'http_server', '2.4.49\\\\:beta', '*']
    """
    parts: list[str] = []
    buf: list[str] = []
    escaped = False
    for ch in cpe:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\":
            buf.append(ch)
            escaped = True
            continue
        if ch == ":":
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    # Un eventuale backslash finale pendente resta nel buffer com'e': lo
    # normalizza unquote().
    parts.append("".join(buf))
    return parts


def unquote(value: str) -> str:
    """Rimuove l'escaping con backslash da un componente CPE.

    ``2.4.49\\:beta`` diventa ``2.4.49:beta``. Un backslash raddoppiato
    (``\\\\``) resta un backslash singolo.
    """
    out: list[str] = []
    escaped = False
    for ch in value:
        if escaped:
            out.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        else:
            out.append(ch)
    if escaped:
        out.append("\\")
    return "".join(out)


def parse_cpe23(cpe: str) -> CPE23:
    """Parsifica una stringa CPE 2.3 restituendo i componenti de-escapati.

    :raises InvalidCPEError: se manca il prefisso ``cpe:2.3:`` o se il numero
        di componenti e' superiore ai 13 previsti.
    """
    if not cpe or not cpe.lower().startswith(CPE_PREFIX):
        raise InvalidCPEError(f"CPE 2.3 non valido: {cpe!r}")

    components = split_components(cpe)[2:]  # scarta 'cpe' e '2.3'
    if len(components) > len(_FIELDS):
        raise InvalidCPEError(
            f"CPE 2.3 con {len(components)} componenti (max {len(_FIELDS)}): {cpe!r}"
        )
    # I CPE troncati esistono nel dizionario NVD: i campi mancanti valgono ANY.
    values = [unquote(c) if c else "*" for c in components]
    values += ["*"] * (len(_FIELDS) - len(values))
    return CPE23(**dict(zip(_FIELDS, values)))


def normalize_name(name: str | None) -> str:
    """Normalizza vendor/product per la ricerca.

    Minuscolo, spazi e trattini convertiti in underscore:
    ``"Apache HTTP Server"`` diventa ``apache_http_server``.
    """
    if not name:
        return ""
    normalized = _NORMALIZE_RE.sub("_", name.strip().lower())
    return _COLLAPSE_RE.sub("_", normalized).strip("_")


#: Alias dei software incontrati piu' spesso in fase di fingerprint.
#: Ogni alias mappa su una o piu' coppie ``(vendor, product)``.
ALIASES: Final[Mapping[str, tuple[tuple[str, str], ...]]] = {
    "httpd": (("apache", "http_server"),),
    "apache2": (("apache", "http_server"),),
    "apache_httpd": (("apache", "http_server"),),
    "apache_http_server": (("apache", "http_server"),),
    "openssh": (("openbsd", "openssh"),),
    "sshd": (("openbsd", "openssh"),),
    "nginx": (("f5", "nginx"), ("nginx", "nginx")),
    "iis": (("microsoft", "internet_information_services"),),
    "internet_information_services": (
        ("microsoft", "internet_information_services"),
    ),
    "mysql": (("oracle", "mysql"),),
    "php": (("php", "php"),),
    "openssl": (("openssl", "openssl"),),
    "tomcat": (("apache", "tomcat"),),
    "apache_tomcat": (("apache", "tomcat"),),
    "exchange": (("microsoft", "exchange_server"),),
    "exchange_server": (("microsoft", "exchange_server"),),
    "postfix": (("postfix", "postfix"),),
    "vsftpd": (("beasts", "vsftpd"),),
    "proftpd": (("proftpd", "proftpd"),),
    "samba": (("samba", "samba"),),
}


def expand_alias(term: str) -> tuple[tuple[str, str], ...]:
    """Espande un alias noto in coppie ``(vendor, product)``.

    Restituisce una tupla vuota se il termine non e' un alias conosciuto.
    """
    return ALIASES.get(normalize_name(term), ())


def known_aliases() -> Iterable[str]:
    """Elenco ordinato degli alias supportati (per l'help della CLI)."""
    return sorted(ALIASES)
