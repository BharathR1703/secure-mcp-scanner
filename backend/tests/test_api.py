"""Tests for the HTTP API.

These exercise the request validation and error mapping without touching
a database: the scan itself needs a live server, which the integration
tests cover.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_the_service_identifies_itself(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "Secure MCP Scanner"
    assert body["version"].startswith("3.")
    assert "postgres" in body["supported_engines"]


def test_health_is_reported(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_the_frameworks_are_listed(client):
    response = client.get("/api/frameworks")
    assert response.status_code == 200
    body = response.json()
    keys = [entry["key"] for entry in body["frameworks"]]
    assert keys == [
        "HIPAA",
        "PCI_DSS",
        "GDPR",
        "DPDP",
        "CCPA",
        "SOC2",
        "ISO27001",
    ]
    assert body["total_controls"] >= 90
    assert body["categories"] == ["PII", "PHI", "PCI"]


def test_the_engines_are_listed(client):
    response = client.get("/api/engines")
    assert response.status_code == 200
    body = response.json()
    assert set(body["engines"]) == {
        "postgres",
        "mysql",
        "sqlite",
        "clickhouse",
        "mongodb",
    }


def test_the_mcp_tools_are_described(client):
    response = client.get("/api/mcp/tools")
    assert response.status_code == 200
    names = [tool["name"] for tool in response.json()["tools"]]
    assert "scan_database_for_pii" in names
    assert "get_compliance_report" in names
    assert "get_audit_report" in names
    assert "list_database_tables" in names


def test_a_connection_string_is_required(client):
    response = client.post("/api/scan", json={})
    assert response.status_code == 422


def test_an_unknown_category_is_rejected(client):
    response = client.post(
        "/api/scan",
        json={
            "connection_string": "postgresql://postgres:postgres@localhost:5432/x",
            "categories": ["NOPE"],
        },
    )
    assert response.status_code == 400
    assert "unknown categories" in response.json()["detail"]


def test_an_unknown_framework_is_rejected(client):
    response = client.post(
        "/api/compliance-report",
        json={
            "connection_string": "postgresql://postgres:postgres@localhost:5432/x",
            "frameworks": ["NOPE"],
        },
    )
    assert response.status_code == 400
    assert "unknown framework" in response.json()["detail"]


def test_an_unsupported_scheme_is_rejected(client):
    response = client.post(
        "/api/scan", json={"connection_string": "oracle://user:pass@host:1521/db"}
    )
    assert response.status_code == 400


def test_a_limit_out_of_range_is_rejected(client):
    response = client.post(
        "/api/scan",
        json={
            "connection_string": "postgresql://postgres:postgres@localhost:5432/x",
            "limit": 5000,
        },
    )
    assert response.status_code == 422


def test_an_audit_report_rejects_an_unknown_format(client):
    response = client.post(
        "/api/audit-report",
        json={
            "connection_string": "postgresql://postgres:postgres@localhost:5432/x",
            "format": "pdf",
        },
    )
    assert response.status_code == 400
