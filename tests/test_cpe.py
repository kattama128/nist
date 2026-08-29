"""Test del parser CPE 2.3 e della normalizzazione dei nomi."""

from __future__ import annotations

import pytest

from nvdlocal.cpe import (
    CPE23,
    InvalidCPEError,
    expand_alias,
    normalize_name,
    parse_cpe23,
    split_components,
    unquote,
)


def test_parse_simple_cpe() -> None:
    cpe = parse_cpe23("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert cpe.part == "a"
    assert cpe.vendor == "apache"
    assert cpe.product == "http_server"
    assert cpe.version == "2.4.49"
    assert cpe.update == "*"
    assert cpe.other == "*"
    assert cpe.vendor_product == "apache:http_server"


def test_parse_cpe_with_escaped_colon() -> None:
    """Uno split(':') ingenuo spezzerebbe la versione in due componenti."""
    cpe = parse_cpe23("cpe:2.3:a:apache:http_server:2.4.49\\:beta:*:*:*:*:*:*:*")
    assert cpe.version == "2.4.49:beta"
    assert cpe.product == "http_server"
    assert cpe.update == "*"


def test_parse_cpe_with_multiple_escapes() -> None:
    cpe = parse_cpe23("cpe:2.3:a:vendor\\:x:prod\\:y:1\\.2\\.3:*:*:*:*:*:*:*")
    assert cpe.vendor == "vendor:x"
    assert cpe.product == "prod:y"
    assert cpe.version == "1.2.3"


def test_parse_cpe_with_escaped_backslash() -> None:
    cpe = parse_cpe23("cpe:2.3:a:vendor:pro\\\\duct:1.0:*:*:*:*:*:*:*")
    assert cpe.product == "pro\\duct"


def test_split_components_respects_escaping() -> None:
    parts = split_components("cpe:2.3:a:apache:http_server:2.4.49\\:beta:*")
    assert parts == ["cpe", "2.3", "a", "apache", "http_server", "2.4.49\\:beta", "*"]


def test_unquote() -> None:
    assert unquote("2.4.49\\:beta") == "2.4.49:beta"
    assert unquote("a\\\\b") == "a\\b"
    assert unquote("plain") == "plain"


def test_parse_truncated_cpe_defaults_to_any() -> None:
    """I CPE troncati esistono nel dizionario NVD: i campi mancanti valgono ANY."""
    cpe = parse_cpe23("cpe:2.3:a:openbsd:openssh:8.2p1")
    assert cpe.version == "8.2p1"
    assert cpe.sw_edition == "*"
    assert cpe.target_hw == "*"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-cpe",
        "cpe:/a:apache:http_server:2.4.49",
        "apache:http_server:2.4.49",
    ],
)
def test_invalid_cpe_raises(value: str) -> None:
    with pytest.raises(InvalidCPEError):
        parse_cpe23(value)


def test_too_many_components_raises() -> None:
    with pytest.raises(InvalidCPEError):
        parse_cpe23("cpe:2.3:" + ":".join(["*"] * 12))


def test_to_string_roundtrip() -> None:
    original = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert parse_cpe23(original).to_string() == original


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Apache HTTP Server", "apache_http_server"),
        ("apache", "apache"),
        ("Internet Information Services", "internet_information_services"),
        ("node-js", "node_js"),
        ("  OpenSSH  ", "openssh"),
        ("Red Hat Enterprise-Linux", "red_hat_enterprise_linux"),
        ("", ""),
        (None, ""),
    ],
)
def test_normalize_name(raw: str | None, expected: str) -> None:
    assert normalize_name(raw) == expected


@pytest.mark.parametrize(
    "alias,expected",
    [
        ("httpd", (("apache", "http_server"),)),
        ("apache2", (("apache", "http_server"),)),
        ("sshd", (("openbsd", "openssh"),)),
        ("OpenSSH", (("openbsd", "openssh"),)),
        ("nginx", (("f5", "nginx"), ("nginx", "nginx"))),
        ("IIS", (("microsoft", "internet_information_services"),)),
        ("mysql", (("oracle", "mysql"),)),
        ("tomcat", (("apache", "tomcat"),)),
        ("exchange", (("microsoft", "exchange_server"),)),
        ("vsftpd", (("beasts", "vsftpd"),)),
        ("samba", (("samba", "samba"),)),
    ],
)
def test_expand_alias(alias: str, expected: tuple[tuple[str, str], ...]) -> None:
    assert expand_alias(alias) == expected


def test_expand_alias_unknown() -> None:
    assert expand_alias("qualcosa_di_ignoto") == ()


def test_cpe_defaults() -> None:
    assert CPE23().to_string() == "cpe:2.3:" + ":".join(["*"] * 11)
