"""Tests for the parser/helper utilities used by checks."""

from __future__ import annotations

from dns_healthcheck.checks._helpers import (
    is_global_ip,
    prefix_diversity,
    valid_hostname,
    valid_label,
)


def test_valid_label_accepts_normal_labels() -> None:
    assert valid_label("example")
    assert valid_label("foo-bar")
    assert valid_label("a")
    assert valid_label("a" * 63)


def test_valid_label_rejects_bad_labels() -> None:
    assert not valid_label("")
    assert not valid_label("a" * 64)
    assert not valid_label("-foo")
    assert not valid_label("foo-")
    assert not valid_label("foo.bar")
    assert not valid_label("foo_bar")


def test_valid_hostname() -> None:
    assert valid_hostname("example.com")
    assert valid_hostname("a.b.c.d.example.com")
    assert valid_hostname("example.com.")
    assert not valid_hostname("foo..bar.com")
    assert not valid_hostname("")


def test_is_global_ip() -> None:
    assert is_global_ip("8.8.8.8")
    assert is_global_ip("2606:4700:4700::1111")
    assert not is_global_ip("10.0.0.1")
    assert not is_global_ip("192.168.1.1")
    assert not is_global_ip("127.0.0.1")
    assert not is_global_ip("not-an-ip")


def test_prefix_diversity_v4() -> None:
    addrs = ["192.0.2.1", "192.0.2.2", "203.0.113.5"]
    assert prefix_diversity(addrs, v4_prefix=24, v6_prefix=48) == 2


def test_prefix_diversity_v6() -> None:
    addrs = ["2001:db8::1", "2001:db8::2", "2001:db9::1"]
    assert prefix_diversity(addrs, v4_prefix=24, v6_prefix=32) == 2
