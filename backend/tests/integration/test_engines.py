"""Integration tests against the live databases.

These run against the five Docker engines the demo ships with. They are
skipped, not failed, when an engine is unreachable: a missing database is
an environment problem, not a defect in the scanner.

Run them with the compose profile::

    docker compose --profile test run --rm tests

or, against databases that are already up::

    pytest tests/integration -q
"""

from __future__ import annotations

import asyncio
import os
import socket
from typing import List, Optional, Tuple

import pytest

from app.mcp_server import run_compliance_report, run_scan_database

#: Where each engine lives. The defaults match the compose service names,
#: so the same tests run inside the ``tests`` container and outside it.
DEFAULT_DSNS = {
    "postgres": "postgresql://postgres:postgres@postgres:5432/sample_db",
    "mysql": "mysql://root:mysql@mysql:3306/sample_db",
    "mongodb": "mongodb://mongo:27017/sample_db",
    "clickhouse": "clickhouse://default:@clickhouse:9000/sample_db",
    "sqlite": "sqlite:////app/data/sample.db",
}


def dsn_for(engine: str) -> str:
    """The DSN for one engine, overridable from the environment."""
    override = os.getenv(f"TEST_DSN_{engine.upper()}")
    if override:
        return override
    return DEFAULT_DSNS[engine]


def _host_port(engine: str) -> Optional[Tuple[str, int]]:
    """The host and port to probe before trying to connect."""
    dsn = dsn_for(engine)
    if engine == "sqlite":
        path = dsn.split(":///", 1)[-1]
        return (os.path.dirname(path) or ".", None)
    if engine == "mongodb":
        authority = dsn.split("://", 1)[-1].split("/", 1)[0]
        host, _, port = authority.partition(":")
        return host, int(port or 27017)
    authority = dsn.split("://", 1)[-1].split("/", 1)[0]
    host, _, port = authority.rpartition("@")[2].partition(":")
    return host or "localhost", int(port or 0)


def engine_is_reachable(engine: str) -> bool:
    """Whether the engine can be reached at all."""
    if engine == "sqlite":
        path = dsn_for("sqlite").split(":///", 1)[-1]
        return os.path.exists(path)
    host, port = _host_port(engine)
    if not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def require_engine(engine: str) -> None:
    """Skip the test when the engine is not running."""
    if not engine_is_reachable(engine):
        pytest.skip(f"{engine} is not reachable at {dsn_for(engine)}")


ENGINES = ["postgres", "mysql", "mongodb", "clickhouse", "sqlite"]


def run(coroutine):
    """Run a coroutine from a synchronous test."""
    return asyncio.run(coroutine)


@pytest.mark.parametrize("engine", ENGINES)
def test_every_engine_can_be_listed(engine):
    require_engine(engine)
    from app.db_connector import list_tables

    references = run(list_tables(dsn_for(engine)))
    names = {reference.name for reference in references}
    assert names, f"{engine} has no relations to scan"


@pytest.mark.parametrize("engine", ENGINES)
def test_every_engine_can_be_scanned(engine):
    require_engine(engine)
    report = run(run_scan_database(dsn_for(engine), limit=25))
    assert report.total_rows_scanned > 0
    assert report.db_type


@pytest.mark.parametrize("engine", ENGINES)
def test_every_engine_finds_personal_data(engine):
    require_engine(engine)
    report = run(run_scan_database(dsn_for(engine), limit=25))
    assert report.total_findings > 0, f"{engine} found nothing to report"


@pytest.mark.parametrize("engine", ENGINES)
def test_every_engine_produces_a_compliance_report(engine):
    require_engine(engine)
    report = run(run_compliance_report(dsn_for(engine), limit=25))
    assert report.overall_status in (
        "COMPLIANT",
        "NON_COMPLIANT",
        "NEEDS_REVIEW",
        "NOT_APPLICABLE",
    )
    assert len(report.frameworks) == 7


@pytest.mark.parametrize("engine", ENGINES)
def test_no_raw_value_ever_leaves_the_scanner(engine):
    """The strongest property of the whole system."""
    require_engine(engine)
    report = run(run_scan_database(dsn_for(engine), limit=25))
    assert report.findings
    for finding in report.findings:
        assert finding.masked_value == "[REDACTED]"

    payload = report.model_dump_json()
    # Values that are in the sample data and must not appear anywhere.
    for secret in (
        "4111111111111111",
        "5500 0055 5555 5559",
        "378282246310005",
        "+919876543210",
        "ananya.sharma@example.com",
        "ABCDE1234F",
        "4589 6231 7452",
    ):
        assert secret not in payload, secret


@pytest.mark.parametrize("engine", ENGINES)
def test_health_data_is_classified_as_phi(engine):
    require_engine(engine)
    report = run(run_scan_database(dsn_for(engine), limit=25))
    classes = report.findings_by_classification
    assert "PHI" in classes, f"{engine} found no protected health information"
    assert "PCI" in classes, f"{engine} found no cardholder data"


@pytest.mark.parametrize("engine", ENGINES)
def test_the_categories_filter_narrows_the_report(engine):
    require_engine(engine)
    everything = run(run_scan_database(dsn_for(engine), limit=25))
    only_phi = run(run_scan_database(dsn_for(engine), limit=25, categories=["PHI"]))
    assert only_phi.total_findings <= everything.total_findings
    for finding in only_phi.findings:
        assert finding.classification == "PHI"


@pytest.mark.parametrize("engine", ENGINES)
def test_the_audit_file_can_be_rendered(engine):
    require_engine(engine)
    from app.compliance.rendering import render

    report = run(run_compliance_report(dsn_for(engine), limit=25))
    html = render(report, "html")
    markdown = render(report, "markdown")
    assert html.startswith("<!doctype html>")
    assert "Compliance audit report" in markdown
