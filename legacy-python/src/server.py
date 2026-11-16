"""MCP server: lightweight SQL Server + Dameng access for LLM clients.

Design notes:
- Connections are configured via env vars (see config.py).
- Multi-connection setups REQUIRE an explicit connection parameter; the
  server refuses to guess and returns a connection catalog instead
  (prevents the LLM silently querying the wrong dev/prod database).
- execute_sql enforces the safety policy in security.py before running.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

from mcp.server.mcpserver import MCPServer

from .config import ConnectionConfig, load_connections, max_rows_limit
from .db import Database, create_connection
from .security import SqlPolicyError, check_identifier, check_sql

mcp = MCPServer(
    "multidb-mcp",
    instructions=(
        "Lightweight MCP server for SQL Server and Dameng (DM8) databases. "
        "Use list_connections first to pick the right connection, then "
        "list_tables / describe_table / execute_sql. execute_sql is read-only "
        "unless the connection is explicitly configured with higher sql_access."
    ),
)

_state: Dict[str, Database] = {}
_catalog: List[ConnectionConfig] = []


def _catalog_text() -> str:
    lines = ["Available connections (pass the 'connection' parameter explicitly):"]
    for c in _catalog:
        label = c.schema or c.database or "-"
        desc = f" -- {c.description}" if c.description else ""
        lines.append(f"  - {c.name} ({c.type}, schema/db: {label}, sql_access: {c.sql_access}){desc}")
    return "\n".join(lines)


def _resolve(connection: str = "") -> ConnectionConfig:
    """Resolve a connection by name with dm8-mcp style explicit routing."""
    if not connection:
        if len(_catalog) == 1:
            return _catalog[0]
        raise ValueError(
            "multiple connections configured; pass the 'connection' parameter explicitly.\n"
            + _catalog_text()
        )
    for c in _catalog:
        if c.name == connection:
            return c
    raise ValueError(
        f"unknown connection: {connection!r}.\n" + _catalog_text()
    )


def _get_db(cfg: ConnectionConfig) -> Database:
    db = _state.get(cfg.name)
    if db is None:
        db = create_connection(cfg)
        db.connect()
        _state[cfg.name] = db
    return db


def _ensure_loaded() -> None:
    global _catalog
    if not _catalog:
        try:
            _catalog = load_connections()
        except ValueError as exc:
            raise RuntimeError(f"configuration error: {exc}") from exc


@mcp.tool()
def list_connections() -> str:
    """List all configured database connections (names, types, schemas, access levels).

    Always call this first when more than one connection exists, so you pick the
    right database before running other tools. Passwords are never returned.
    """
    _ensure_loaded()
    return json.dumps([c.safe_summary() for c in _catalog], ensure_ascii=False, indent=2)


@mcp.tool()
def test_connection(connection: str = "") -> str:
    """Test connectivity to one database connection and return server info.

    Pass 'connection' by name; with a single connection it can be omitted.
    Returns database type, version, current schema/database and login user.
    """
    _ensure_loaded()
    cfg = _resolve(connection)
    db = _get_db(cfg)
    info = db.server_info()
    info["connection"] = cfg.name
    info["sql_access"] = cfg.sql_access
    return json.dumps(info, ensure_ascii=False, indent=2)


@mcp.tool()
def list_tables(connection: str = "", schema: str = "") -> str:
    """List tables in a schema.

    'connection' selects the configured connection (required when multiple are
    configured). 'schema' filters to a specific schema; omit for the default
    schema of the connection.
    """
    _ensure_loaded()
    cfg = _resolve(connection)
    if schema:
        check_identifier(schema)
    db = _get_db(cfg)
    tables = db.list_tables(schema or cfg.schema or cfg.database)
    return json.dumps(
        {"connection": cfg.name, "schema": schema or cfg.schema or cfg.database, "tables": tables},
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
def describe_table(table: str, connection: str = "", schema: str = "") -> str:
    """Describe a table: column names, types, lengths, nullability, defaults, comments.

    'table' is required. 'connection' and 'schema' select where the table lives
    (required when multiple connections are configured).
    """
    _ensure_loaded()
    cfg = _resolve(connection)
    check_identifier(table)
    if schema:
        check_identifier(schema)
    db = _get_db(cfg)
    result = db.describe_table(table, schema or cfg.schema or cfg.database)
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
def execute_sql(sql: str, connection: str = "", max_rows: int = 0) -> str:
    """Execute a single SQL statement and return the result.

    Only ONE statement per call. Statements are validated against the
    connection's sql_access level: 'readonly' allows only SELECT/WITH/
    EXPLAIN/SHOW/DESCRIBE; higher levels (dml/ddl/full) must be configured
    explicitly for the connection. Returns columns, rows and whether the
    result was truncated by the row cap.
    """
    _ensure_loaded()
    cfg = _resolve(connection)
    try:
        check_sql(sql, cfg.sql_access)
    except SqlPolicyError as exc:
        return json.dumps(
            {"error": str(exc), "sql_access": cfg.sql_access, "connection": cfg.name},
            ensure_ascii=False,
            indent=2,
        )
    limit = min(max(max_rows, 0), max_rows_limit()) if max_rows else max_rows_limit()
    db = _get_db(cfg)
    try:
        result = db.execute(sql, limit)
    except Exception as exc:
        return json.dumps(
            {"error": f"{type(exc).__name__}: {exc}", "connection": cfg.name},
            ensure_ascii=False,
            indent=2,
        )
    result["connection"] = cfg.name
    return json.dumps(result, ensure_ascii=False, indent=2)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
