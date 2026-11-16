"""Connection configuration parsing for multidb-mcp.

Two configuration modes (env vars):

1. Multi-connection mode (preferred when you have more than one DB):
   DB_CONNECTIONS = JSON array, e.g.
   [{"name":"dev","type":"dameng","host":"192.168.0.30","port":5236,
     "user":"SYSDBA","password":"***","schema":"SYSDBA",
     "description":"开发环境","sql_access":"readonly"},
    {"name":"prod","type":"sqlserver","host":"10.0.0.5","port":1433,
     "user":"sa","password":"***","database":"HBDB",
     "description":"生产库","sql_access":"readonly"}]

2. Single-connection shorthand:
   DB_TYPE / DB_HOST / DB_PORT / DB_USER / DB_PASSWORD,
   plus DB_SCHEMA (dameng) or DB_DATABASE (sqlserver).

Global switches:
   DB_SQL_ACCESS  default sql_access for connections without explicit setting
                  (readonly / dml / ddl / full, default readonly)
   DB_MAX_ROWS    default and hard cap for rows returned by execute_sql
                  (default 1000, hard cap 10000)
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import List

ACCESS_LEVELS = ("readonly", "dml", "ddl", "full")
SUPPORTED_TYPES = ("dameng", "sqlserver")

DEFAULT_PORTS = {"dameng": 5236, "sqlserver": 1433}


@dataclass
class ConnectionConfig:
    name: str
    type: str            # dameng | sqlserver
    host: str
    port: int
    user: str
    password: str
    schema: str = ""     # dameng: schema name
    database: str = ""   # sqlserver: database name
    description: str = ""
    sql_access: str = "readonly"

    def safe_summary(self) -> dict:
        """Connection info safe to show to the LLM (never includes password)."""
        return {
            "name": self.name,
            "type": self.type,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "schema": self.schema or self.database,
            "description": self.description,
            "sql_access": self.sql_access,
        }


def _parse_int(value, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _check_access(access: str, who: str) -> str:
    access = (access or "readonly").strip().lower()
    if access not in ACCESS_LEVELS:
        raise ValueError(
            f"invalid sql_access for '{who}': {access!r} "
            f"(allowed: {', '.join(ACCESS_LEVELS)})"
        )
    return access


def load_connections() -> List[ConnectionConfig]:
    """Load connection list from environment. Raises ValueError on bad config."""
    raw = os.environ.get("DB_CONNECTIONS", "").strip()
    default_access = _check_access(os.environ.get("DB_SQL_ACCESS", "readonly"), "DB_SQL_ACCESS")

    if raw:
        try:
            items = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"DB_CONNECTIONS is not valid JSON: {exc}") from exc
        if not isinstance(items, list) or not items:
            raise ValueError("DB_CONNECTIONS must be a non-empty JSON array")

        connections: List[ConnectionConfig] = []
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(f"DB_CONNECTIONS entry #{idx + 1} must be a JSON object")
            name = str(item.get("name") or f"conn{idx + 1}")
            db_type = str(item.get("type", "dameng")).strip().lower()
            if db_type not in SUPPORTED_TYPES:
                raise ValueError(
                    f"connection '{name}': unsupported type {db_type!r} "
                    f"(allowed: {', '.join(SUPPORTED_TYPES)})"
                )
            if not item.get("host"):
                raise ValueError(f"connection '{name}': 'host' is required")
            connections.append(ConnectionConfig(
                name=name,
                type=db_type,
                host=str(item["host"]),
                port=_parse_int(item.get("port"), DEFAULT_PORTS[db_type]),
                user=str(item.get("user", "")),
                password=str(item.get("password", "")),
                schema=str(item.get("schema", "")),
                database=str(item.get("database", "")),
                description=str(item.get("description", "")),
                sql_access=_check_access(item.get("sql_access", ""), name) or default_access,
            ))
        return connections

    # Single-connection shorthand mode
    db_type = os.environ.get("DB_TYPE", "dameng").strip().lower()
    if db_type not in SUPPORTED_TYPES:
        raise ValueError(
            f"DB_TYPE must be one of {', '.join(SUPPORTED_TYPES)}, got: {db_type!r}"
        )
    if not os.environ.get("DB_HOST"):
        raise ValueError("DB_HOST is required (or use DB_CONNECTIONS)")
    return [ConnectionConfig(
        name="default",
        type=db_type,
        host=os.environ["DB_HOST"],
        port=_parse_int(os.environ.get("DB_PORT"), DEFAULT_PORTS[db_type]),
        user=os.environ.get("DB_USER", ""),
        password=os.environ.get("DB_PASSWORD", ""),
        schema=os.environ.get("DB_SCHEMA", ""),
        database=os.environ.get("DB_DATABASE", ""),
        description=os.environ.get("DB_DESCRIPTION", ""),
        sql_access=default_access,
    )]


def max_rows_limit() -> int:
    """Default row cap for execute_sql, clamped to a hard cap of 10000."""
    return min(_parse_int(os.environ.get("DB_MAX_ROWS"), 1000), 10000)
