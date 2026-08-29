"""Comparatore di versioni "naturale" per le stringhe che compaiono nei CPE.

Le versioni dentro i CPE non seguono PEP 440 (``8.5p1``, ``2.4.53-1ubuntu1``,
``0.9.8zh``, ``1.0-rc1``), quindi ``packaging.version`` da solo non basta.

Regole implementate:

* tokenizzazione in sequenze alternate di cifre e lettere, i separatori
  (``.``, ``-``, ``_``, ``+``, ``~``) fanno solo da delimitatori;
* confronto numerico fra numeri, lessicografico fra stringhe;
* a parita' di posizione un numero e' **minore** di una stringa
  (``1.2.3a > 1.2.3``, ``8.5p1 > 8.5``);
* padding con zeri delle liste piu' corte, quindi ``1.0 == 1.0.0``;
* i marcatori di pre-release (``alpha``, ``beta``, ``rc``, ``pre``, ``dev``,
  ``snapshot``) sono **minori** sia dei numeri sia delle altre stringhe,
  quindi ``1.0-rc1 < 1.0``;
* i valori speciali CPE ``*`` (ANY) e ``-`` (NA) non sono versioni e vanno
  intercettati prima del confronto (:func:`is_special`).
"""

from __future__ import annotations

import re
from typing import Final, Sequence, Union

__all__ = [
    "ANY",
    "NA",
    "Token",
    "compare",
    "is_any",
    "is_concrete",
    "is_na",
    "is_special",
    "tokenize",
]

ANY: Final[str] = "*"
NA: Final[str] = "-"

#: Token = numero (int) oppure identificatore alfabetico (str minuscola).
Token = Union[int, str]

_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\d+|[A-Za-z]+")

#: Ordinamento relativo dei marcatori di pre-release (piu' basso = piu' vecchio).
_PRERELEASE_RANK: Final[dict[str, int]] = {
    "dev": 0,
    "snapshot": 1,
    "alpha": 2,
    "beta": 3,
    "pre": 4,
    "rc": 5,
}


def is_any(value: str | None) -> bool:
    """True se il valore CPE e' il wildcard ANY (``*``)."""
    return value is None or value.strip() in ("", ANY)


def is_na(value: str | None) -> bool:
    """True se il valore CPE e' NA (``-``), cioe' "non applicabile"."""
    return value is not None and value.strip() == NA


def is_special(value: str | None) -> bool:
    """True se il valore e' un valore speciale CPE (``*`` o ``-``) o vuoto."""
    return is_any(value) or is_na(value)


def is_concrete(value: str | None) -> bool:
    """True se il valore e' una versione confrontabile e non un valore speciale."""
    return not is_special(value)


def tokenize(version: str) -> list[Token]:
    """Scompone una versione in token alternati numerici/alfabetici.

    >>> tokenize("8.5p1")
    [8, 5, 'p', 1]
    >>> tokenize("2.4.53-1ubuntu1")
    [2, 4, 53, 1, 'ubuntu', 1]
    """
    return [
        int(tok) if tok.isdigit() else tok.lower()
        for tok in _TOKEN_RE.findall(version)
    ]


def _is_prerelease(token: Token) -> bool:
    return isinstance(token, str) and token in _PRERELEASE_RANK


def _cmp_token(a: Token, b: Token) -> int:
    """Confronta due token secondo le regole descritte nel modulo."""
    a_pre, b_pre = _is_prerelease(a), _is_prerelease(b)
    if a_pre and b_pre:
        rank_a, rank_b = _PRERELEASE_RANK[str(a)], _PRERELEASE_RANK[str(b)]
        return (rank_a > rank_b) - (rank_a < rank_b)
    if a_pre:  # una pre-release e' minore di qualsiasi numero o stringa normale
        return -1
    if b_pre:
        return 1

    a_num, b_num = isinstance(a, int), isinstance(b, int)
    if a_num and b_num:
        return (a > b) - (a < b)  # type: ignore[operator]
    if a_num:  # numero < stringa a parita' di posizione
        return -1
    if b_num:
        return 1
    return (str(a) > str(b)) - (str(a) < str(b))


def _cmp_tokens(a: Sequence[Token], b: Sequence[Token]) -> int:
    for i in range(max(len(a), len(b))):
        # padding con zeri: 1.0 == 1.0.0, e 1.0-rc1 < 1.0 perche' rc < 0
        left: Token = a[i] if i < len(a) else 0
        right: Token = b[i] if i < len(b) else 0
        result = _cmp_token(left, right)
        if result:
            return result
    return 0


def compare(a: str, b: str) -> int:
    """Confronta due versioni: ``-1`` se ``a < b``, ``0`` se uguali, ``1`` se ``a > b``.

    :raises ValueError: se una delle due e' un valore speciale CPE (``*``/``-``)
        o una stringa priva di token confrontabili.
    """
    if is_special(a) or is_special(b):
        raise ValueError(
            f"valori speciali CPE non confrontabili: {a!r} / {b!r} "
            "(vanno gestiti prima del confronto)"
        )
    tokens_a, tokens_b = tokenize(a), tokenize(b)
    if not tokens_a or not tokens_b:
        raise ValueError(f"versione non tokenizzabile: {a!r} / {b!r}")
    return _cmp_tokens(tokens_a, tokens_b)
