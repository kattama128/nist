"""Test del comparatore di versioni."""

from __future__ import annotations

import pytest

from nvdlocal.versions import compare, is_any, is_concrete, is_na, is_special, tokenize


@pytest.mark.parametrize(
    "left,right,expected",
    [
        # Casi richiesti esplicitamente dalle specifiche.
        ("2.4.52", "2.4.53", -1),
        ("1.0", "1.0.0", 0),
        ("8.5p1", "8.5", 1),
        ("1.0-rc1", "1.0", -1),
        ("2.4.9", "2.4.10", -1),
        ("1.2.3a", "1.2.3", 1),
        ("9.0", "10.0", -1),
        ("0.9.8zh", "0.9.8h", 1),
        # Confronti numerici di base.
        ("2.4.53", "2.4.52", 1),
        ("2.4.52", "2.4.52", 0),
        ("1.20.0", "1.9.9", 1),
        ("10.0", "9.0", 1),
        # Padding con zeri.
        ("1.0.0.0", "1", 0),
        ("2.4", "2.4.0.0", 0),
        # Suffissi di patch (OpenSSH usa 8.2p1).
        ("8.2p1", "8.2p2", -1),
        ("8.2p1", "8.3", -1),
        ("8.5", "8.5p1", -1),
        # Pre-release: sempre minori della release finale.
        ("1.0-alpha", "1.0", -1),
        ("1.0-beta", "1.0-rc1", -1),
        ("1.0-alpha", "1.0-beta", -1),
        ("2.0-dev", "2.0-snapshot", -1),
        ("1.0-rc2", "1.0-rc10", -1),
        ("1.0-pre", "1.0", -1),
        ("3.0.0-beta", "3.0.0", -1),
        # Suffissi non di pre-release: maggiori.
        ("1.2.3a", "1.2.3b", -1),
        ("0.9.8h", "0.9.8zh", -1),
        # Versioni di distribuzione.
        ("2.4.53-1ubuntu1", "2.4.53", 1),
        ("2.4.53-1ubuntu1", "2.4.54", -1),
        ("2.4.52-1ubuntu4.3", "2.4.52-1ubuntu4.2", 1),
    ],
)
def test_compare(left: str, right: str, expected: int) -> None:
    assert compare(left, right) == expected
    assert compare(right, left) == -expected


def test_nine_is_not_greater_than_ten() -> None:
    """Il caso classico dell'ordinamento lessicografico sbagliato."""
    assert (compare("9.0", "10.0") > 0) is False


@pytest.mark.parametrize(
    "version,expected",
    [
        ("8.5p1", [8, 5, "p", 1]),
        ("2.4.52", [2, 4, 52]),
        ("2.4.53-1ubuntu1", [2, 4, 53, 1, "ubuntu", 1]),
        ("1.0-rc1", [1, 0, "rc", 1]),
        ("0.9.8zh", [0, 9, 8, "zh"]),
        ("1.0.0", [1, 0, 0]),
    ],
)
def test_tokenize(version: str, expected: list[object]) -> None:
    assert tokenize(version) == expected


@pytest.mark.parametrize("value", ["*", "-", "", "  "])
def test_special_values_are_rejected_by_compare(value: str) -> None:
    """I valori speciali CPE vanno gestiti prima del confronto."""
    with pytest.raises(ValueError):
        compare(value, "1.0")
    with pytest.raises(ValueError):
        compare("1.0", value)


def test_unparsable_version_raises() -> None:
    with pytest.raises(ValueError):
        compare("...", "1.0")


def test_special_value_helpers() -> None:
    assert is_any("*") and is_any("") and is_any(None)
    assert is_na("-")
    assert is_special("*") and is_special("-")
    assert not is_special("2.4.52")
    assert is_concrete("2.4.52")
    assert not is_concrete("*")


def test_compare_is_transitive_on_a_release_line() -> None:
    """Ordinamento coerente su una sequenza di release reali di httpd."""
    releases = [
        "2.4.9",
        "2.4.10",
        "2.4.46",
        "2.4.49",
        "2.4.51",
        "2.4.52",
        "2.4.53",
        "2.4.54",
    ]
    import functools

    ordered = sorted(releases, key=functools.cmp_to_key(compare))
    assert ordered == releases
