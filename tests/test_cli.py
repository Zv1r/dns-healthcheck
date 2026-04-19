"""CLI sanity tests via Typer's CliRunner."""

from __future__ import annotations

from typer.testing import CliRunner

from dns_healthcheck import __version__
from dns_healthcheck.cli import app


def test_version_flag() -> None:
    r = CliRunner().invoke(app, ["--version"])
    assert r.exit_code == 0
    assert __version__ in r.stdout


def test_list_checks_table() -> None:
    r = CliRunner().invoke(app, ["list-checks"])
    assert r.exit_code == 0
    assert "BASIC01" in r.stdout
    assert "DNSSEC01" in r.stdout


def test_list_checks_json() -> None:
    import json as _j

    r = CliRunner().invoke(app, ["list-checks", "--format", "json"])
    assert r.exit_code == 0
    data = _j.loads(r.stdout)
    assert isinstance(data, list)
    assert len(data) >= 91
    assert all("id" in d and "category" in d for d in data)


def test_explain() -> None:
    r = CliRunner().invoke(app, ["explain", "DELEGATION01"])
    assert r.exit_code == 0
    assert "DELEGATION01" in r.stdout


def test_list_profiles() -> None:
    r = CliRunner().invoke(app, ["list-profiles"])
    assert r.exit_code == 0
    assert "default" in r.stdout
    assert "strict" in r.stdout


def test_unknown_profile_errors() -> None:
    r = CliRunner().invoke(app, ["check", "example.com", "--profile", "nosuch"])
    assert r.exit_code != 0
