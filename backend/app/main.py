"""FastAPI application exposing the Secure MCP Scanner tools over HTTP."""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .compliance.frameworks import framework_summaries, total_control_count
from .db import SUPPORTED_ENGINES, supported_schemes
from .db_connector import (
    DatabaseConnectionError,
    DatabaseQueryError,
    UnsupportedDatabaseError,
    close_all_pools,
)
from .mcp_server import (
    mcp,
    render_audit,
    run_compliance_report,
    run_list_tables,
    run_scan_database,
)
from .models import (
    ComplianceReport,
    ScanRequest,
    ScanReport,
    TableListResponse,
)

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("secure-mcp-scanner")

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "*").split(",")
    if origin.strip()
]

MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "scan_database_for_pii",
        "description": (
            "Connect to a database, sample rows from a table (or every "
            "table) and detect personal, health and cardholder data "
            "(emails, phone numbers, PAN, Aadhaar, names, diagnoses, card "
            "numbers). Values are masked before they are returned."
        ),
        "endpoint": "/api/mcp/scan_database_for_pii",
        "parameters": [
            "connection_string",
            "table_name (optional; omit to scan every table)",
            "limit (optional, default 100)",
            "db_type (optional, default inferred from the DSN)",
            "categories (optional; PII, PHI and/or PCI)",
        ],
    },
    {
        "name": "get_compliance_report",
        "description": (
            "Scan a database and assess it against HIPAA, PCI DSS, GDPR, "
            "DPDP, CCPA, SOC 2 and ISO 27001, control by control."
        ),
        "endpoint": "/api/mcp/get_compliance_report",
        "parameters": [
            "connection_string",
            "table_name (optional; omit to scan every table)",
            "limit (optional, default 100)",
            "db_type (optional, default inferred from the DSN)",
            "categories (optional; PII, PHI and/or PCI)",
            "frameworks (optional; default all seven)",
        ],
    },
    {
        "name": "get_audit_report",
        "description": (
            "Produce a self-contained audit file -- HTML for a human, "
            "Markdown for a pipeline -- from a database scan."
        ),
        "endpoint": "/api/mcp/get_audit_report",
        "parameters": [
            "connection_string",
            "table_name (optional; omit to scan every table)",
            "limit (optional, default 100)",
            "db_type (optional, default inferred from the DSN)",
            "categories (optional; PII, PHI and/or PCI)",
            "frameworks (optional; default all seven)",
            "format (optional; html or markdown)",
        ],
    },
    {
        "name": "list_database_tables",
        "description": (
            "List every table, view or collection that can be scanned in a "
            "database."
        ),
        "endpoint": "/api/mcp/list_database_tables",
        "parameters": ["connection_string", "db_type (optional)"],
    },
]


class ListTablesRequest(BaseModel):
    """Request body for the table-listing endpoint."""

    connection_string: str = Field(..., description="Database DSN")
    db_type: Optional[str] = Field(
        default=None, description="Force an engine instead of inferring it"
    )


class AuditReportRequest(ScanRequest):
    """Request body for the downloadable audit file."""

    format: str = Field(
        default="html",
        description="Audit file format: 'html' or 'markdown'.",
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger.info("Secure MCP Scanner starting up")
    yield
    await close_all_pools()
    logger.info("Secure MCP Scanner shut down; database pools closed")


app = FastAPI(
    title="Secure MCP Scanner",
    description=(
        "Production-ready MCP server with built-in PII masking and async "
        "database connectors. Scans Postgres, MySQL, SQLite, ClickHouse and "
        "MongoDB for personal data, protected health information and "
        "cardholder data, and assesses what it finds against HIPAA, PCI "
        "DSS, GDPR, DPDP, CCPA, SOC 2 and ISO 27001."
    ),
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MCP integration: mount the SDK's SSE transport when available. The MCP
# tools are also reachable over stdio via `python -m app.mcp_server`.
try:
    app.mount("/mcp", mcp.sse_app())
    logger.info("MCP SSE transport mounted at /mcp/sse")
except Exception:
    logger.info("MCP SSE transport unavailable; tools exposed over HTTP and stdio")


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, UnsupportedDatabaseError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, DatabaseConnectionError):
        return HTTPException(status_code=502, detail=str(exc))
    if isinstance(exc, DatabaseQueryError):
        return HTTPException(status_code=400, detail=str(exc))
    logger.exception("Unexpected error while scanning")
    return HTTPException(status_code=500, detail="Unexpected server error while scanning")


@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "service": "Secure MCP Scanner",
        "version": "3.0.0",
        "docs": "/docs",
        "health": "/health",
        "supported_engines": SUPPORTED_ENGINES,
        "supported_schemes": supported_schemes(),
        "frameworks": [entry["key"] for entry in framework_summaries()],
    }


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "healthy", "service": "secure-mcp-scanner"}


@app.get("/api/engines")
async def list_engines() -> Dict[str, Any]:
    """List the database engines the scanner can connect to."""
    return {
        "engines": SUPPORTED_ENGINES,
        "schemes": supported_schemes(),
    }


@app.get("/api/frameworks")
async def list_frameworks() -> Dict[str, Any]:
    """List the regulatory frameworks the scanner assesses against."""
    return {
        "frameworks": framework_summaries(),
        "total_controls": total_control_count(),
        "categories": ["PII", "PHI", "PCI"],
    }


@app.post("/api/scan", response_model=ScanReport)
async def scan(request: ScanRequest) -> ScanReport:
    """Scan a table -- or every table -- for regulated data.

    Findings are returned masked, and each one carries the regulatory
    class it was classified as.
    """
    logger.info(
        "Scan requested for %s (limit=%d, categories=%s)",
        request.table_name or "all tables",
        request.limit,
        request.categories or "all",
    )
    try:
        return await run_scan_database(
            request.connection_string,
            request.table_name,
            request.limit,
            request.db_type,
            request.max_tables,
            request.categories,
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@app.post("/api/compliance-report", response_model=ComplianceReport)
async def compliance_report(request: ScanRequest) -> ComplianceReport:
    """Scan a database and return the control-level compliance assessment.

    The scan runs once; the assessment reads from that result.
    """
    logger.info(
        "Compliance report requested for %s (limit=%d, categories=%s, "
        "frameworks=%s)",
        request.table_name or "all tables",
        request.limit,
        request.categories or "all",
        request.frameworks or "all",
    )
    try:
        return await run_compliance_report(
            request.connection_string,
            request.table_name,
            request.limit,
            request.db_type,
            request.max_tables,
            request.categories,
            request.frameworks,
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@app.post("/api/audit-report")
async def audit_report(request: AuditReportRequest) -> Response:
    """Return a downloadable, self-contained audit file.

    The HTML version has inline CSS and a print stylesheet: it opens in a
    browser and prints to PDF with nothing to fetch. The Markdown version
    carries the same content for pipelines and agents.
    """
    normalised = (request.format or "html").lower()
    if normalised not in ("html", "markdown", "md"):
        raise HTTPException(
            status_code=400, detail="format must be 'html' or 'markdown'"
        )
    extension = "md" if normalised in ("markdown", "md") else "html"
    try:
        report = await run_compliance_report(
            request.connection_string,
            request.table_name,
            request.limit,
            request.db_type,
            request.max_tables,
            request.categories,
            request.frameworks,
        )
    except Exception as exc:
        raise _http_error(exc) from exc

    content = render_audit(report, normalised)
    media_type = (
        "text/markdown; charset=utf-8"
        if extension == "md"
        else "text/html; charset=utf-8"
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": (
                f'attachment; filename="compliance-audit.{extension}"'
            )
        },
    )


@app.post("/api/tables", response_model=TableListResponse)
async def tables(request: ListTablesRequest) -> TableListResponse:
    """List every table, view or collection available for scanning."""
    try:
        return await run_list_tables(request.connection_string, request.db_type)
    except Exception as exc:
        raise _http_error(exc) from exc


@app.get("/api/mcp/tools")
async def list_mcp_tools() -> Dict[str, Any]:
    """Describe the MCP tools and their HTTP equivalents."""
    return {"tools": MCP_TOOLS}


@app.post("/api/mcp/scan_database_for_pii", response_model=ScanReport)
async def mcp_scan_database_for_pii(request: ScanRequest) -> ScanReport:
    """HTTP mirror of the MCP tool ``scan_database_for_pii``."""
    try:
        return await run_scan_database(
            request.connection_string,
            request.table_name,
            request.limit,
            request.db_type,
            request.max_tables,
            request.categories,
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@app.post("/api/mcp/get_compliance_report", response_model=ComplianceReport)
async def mcp_get_compliance_report(request: ScanRequest) -> ComplianceReport:
    """HTTP mirror of the MCP tool ``get_compliance_report``."""
    try:
        return await run_compliance_report(
            request.connection_string,
            request.table_name,
            request.limit,
            request.db_type,
            request.max_tables,
            request.categories,
            request.frameworks,
        )
    except Exception as exc:
        raise _http_error(exc) from exc


@app.post("/api/mcp/get_audit_report")
async def mcp_get_audit_report(request: AuditReportRequest) -> Dict[str, Any]:
    """HTTP mirror of the MCP tool ``get_audit_report``."""
    normalised = (request.format or "html").lower()
    if normalised not in ("html", "markdown", "md"):
        raise HTTPException(
            status_code=400, detail="format must be 'html' or 'markdown'"
        )
    extension = "md" if normalised in ("markdown", "md") else "html"
    try:
        report = await run_compliance_report(
            request.connection_string,
            request.table_name,
            request.limit,
            request.db_type,
            request.max_tables,
            request.categories,
            request.frameworks,
        )
    except Exception as exc:
        raise _http_error(exc) from exc
    return {
        "format": normalised,
        "filename": f"compliance-audit.{extension}",
        "content": render_audit(report, normalised),
    }


@app.post("/api/mcp/list_database_tables", response_model=TableListResponse)
async def mcp_list_database_tables(request: ListTablesRequest) -> TableListResponse:
    """HTTP mirror of the MCP tool ``list_database_tables``."""
    try:
        return await run_list_tables(request.connection_string, request.db_type)
    except Exception as exc:
        raise _http_error(exc) from exc
