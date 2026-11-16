"""Database connection abstraction: Dameng (DM8) and SQL Server.

Both backends implement the same small interface:
    connect(cfg) / close()
    server_info()            -> dict (version, current schema/database, user)
    list_tables(schema)      -> list[str]
    describe_table(table, schema) -> dict {columns: [...], table_comment: str}
    execute(sql, max_rows)   -> dict {columns, rows, row_count, truncated}
"""
from __future__ import annotations

import datetime
import decimal
from typing import Any, Dict, List, Optional

from .config import ConnectionConfig


def _jsonable(value: Any) -> Any:
    """Convert DB values to JSON-serializable forms."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat(sep=" ") if isinstance(value, datetime.datetime) else value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


class Database:
    type = ""

    def __init__(self, cfg: ConnectionConfig):
        self.cfg = cfg
        self._conn = None

    # -- lifecycle -----------------------------------------------------------
    def connect(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # -- helpers -------------------------------------------------------------
    def _ensure(self):
        if self._conn is None:
            self.connect()
        return self._conn

    def _set_context(self, schema: str) -> None:
        """Switch the session context (schema / database)."""
        raise NotImplementedError

    # -- operations ---------------------------------------------------------
    def server_info(self) -> Dict[str, Any]:
        raise NotImplementedError

    def list_tables(self, schema: str = "") -> List[str]:
        raise NotImplementedError

    def describe_table(self, table: str, schema: str = "") -> Dict[str, Any]:
        raise NotImplementedError

    def execute(self, sql: str, max_rows: int) -> Dict[str, Any]:
        raise NotImplementedError


class DamengDB(Database):
    type = "dameng"

    def connect(self) -> None:
        import dmPython

        self._conn = dmPython.connect(
            host=self.cfg.host,
            port=self.cfg.port,
            user=self.cfg.user,
            password=self.cfg.password,
        )
        if self.cfg.schema:
            self._set_context(self.cfg.schema)

    def _set_context(self, schema: str) -> None:
        cur = self._ensure().cursor()
        cur.execute(f'SET SCHEMA "{schema}"')
        cur.close()

    def server_info(self) -> Dict[str, Any]:
        conn = self._ensure()
        cur = conn.cursor()
        cur.execute("SELECT BANNER FROM V$VERSION WHERE ROWNUM <= 1")
        row = cur.fetchone()
        cur.execute("SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL")
        schema_row = cur.fetchone()
        cur.execute("SELECT USER FROM DUAL")
        user_row = cur.fetchone()
        cur.close()
        return {
            "type": self.type,
            "version": row[0] if row else "",
            "current_schema": schema_row[0] if schema_row else "",
            "user": user_row[0] if user_row else self.cfg.user,
        }

    def list_tables(self, schema: str = "") -> List[str]:
        conn = self._ensure()
        cur = conn.cursor()
        if schema:
            cur.execute(
                "SELECT TABLE_NAME FROM ALL_TABLES WHERE UPPER(OWNER) = UPPER(?) ORDER BY TABLE_NAME",
                (schema,),
            )
        else:
            cur.execute("SELECT TABLE_NAME FROM USER_TABLES ORDER BY TABLE_NAME")
        rows = [r[0] for r in cur.fetchall()]
        cur.close()
        return rows

    def describe_table(self, table: str, schema: str = "") -> Dict[str, Any]:
        conn = self._ensure()
        cur = conn.cursor()
        owner = schema or self.cfg.schema or "SYSDBA"
        cur.execute(
            """
            SELECT COLUMN_NAME, DATA_TYPE, CHAR_LENGTH, NULLABLE, DATA_DEFAULT,
                   (SELECT COMMENTS FROM ALL_COL_COMMENTS
                     WHERE OWNER = ? AND TABLE_NAME = ? AND COLUMN_NAME = A.COLUMN_NAME)
              FROM ALL_TAB_COLUMNS A
             WHERE UPPER(OWNER) = UPPER(?) AND UPPER(TABLE_NAME) = UPPER(?)
             ORDER BY COLUMN_ID
            """,
            (owner, table, owner, table),
        )
        columns = [
            {
                "name": r[0],
                "type": r[1],
                "length": _jsonable(r[2]),
                "nullable": r[3] == "Y",
                "default": _jsonable(r[4]),
                "comment": _jsonable(r[5]) or "",
            }
            for r in cur.fetchall()
        ]
        cur.execute(
            "SELECT COMMENTS FROM ALL_TAB_COMMENTS WHERE UPPER(OWNER) = UPPER(?) AND UPPER(TABLE_NAME) = UPPER(?)",
            (owner, table),
        )
        row = cur.fetchone()
        cur.close()
        return {"table": table, "schema": owner, "columns": columns, "table_comment": row[0] if row else ""}

    def execute(self, sql: str, max_rows: int) -> Dict[str, Any]:
        conn = self._ensure()
        cur = conn.cursor()
        cur.execute(sql)
        if cur.description is None:
            # non-query statement (DML/DDL): report affected rows
            cur.close()
            return {"columns": [], "rows": [], "row_count": 0, "affected_rows": cur.rowcount}
        rows = cur.fetchmany(max_rows + 1)
        truncated = len(rows) > max_rows
        rows = rows[:max_rows]
        columns = [d[0] for d in cur.description]
        data = [[_jsonable(v) for v in row] for row in rows]
        cur.close()
        return {"columns": columns, "rows": data, "row_count": len(data), "truncated": truncated}


class SqlServerDB(Database):
    type = "sqlserver"

    def connect(self) -> None:
        try:
            import pymssql
        except ImportError as exc:
            raise RuntimeError(
                "pymssql is not installed. Install it with: pip install pymssql"
            ) from exc
        self._conn = pymssql.connect(
            server=self.cfg.host,
            port=self.cfg.port,
            user=self.cfg.user,
            password=self.cfg.password,
            database=self.cfg.database or None,
            charset="utf8",
            as_dict=True,
        )

    def _set_context(self, schema: str) -> None:
        # For SQL Server the "context" is the database; schema is a naming scope.
        if self.cfg.database:
            cur = self._ensure().cursor()
            cur.execute(f"USE [{self.cfg.database}]")
            cur.close()

    def server_info(self) -> Dict[str, Any]:
        conn = self._ensure()
        cur = conn.cursor()
        cur.execute("SELECT @@VERSION AS v, SYSTEM_USER AS u, DB_NAME() AS d")
        row = cur.fetchone()
        cur.close()
        return {
            "type": self.type,
            "version": row["v"] if row else "",
            "current_schema": row["d"] if row else self.cfg.database,
            "user": row["u"] if row else self.cfg.user,
        }

    def list_tables(self, schema: str = "") -> List[str]:
        conn = self._ensure()
        cur = conn.cursor()
        if schema:
            cur.execute(
                "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME",
                (schema,),
            )
        else:
            cur.execute(
                "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME"
            )
        rows = [r["TABLE_NAME"] for r in cur.fetchall()]
        cur.close()
        return rows

    def describe_table(self, table: str, schema: str = "") -> Dict[str, Any]:
        conn = self._ensure()
        cur = conn.cursor()
        owner = schema or "dbo"
        cur.execute(
            """
            SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE,
                   COLUMN_DEFAULT
              FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
             ORDER BY ORDINAL_POSITION
            """,
            (owner, table),
        )
        columns = [
            {
                "name": r["COLUMN_NAME"],
                "type": r["DATA_TYPE"],
                "length": _jsonable(r["CHARACTER_MAXIMUM_LENGTH"]),
                "nullable": r["IS_NULLABLE"] == "YES",
                "default": _jsonable(r["COLUMN_DEFAULT"]),
                "comment": "",
            }
            for r in cur.fetchall()
        ]
        cur.close()
        return {"table": table, "schema": owner, "columns": columns, "table_comment": ""}

    def execute(self, sql: str, max_rows: int) -> Dict[str, Any]:
        conn = self._ensure()
        cur = conn.cursor()
        cur.execute(sql)
        if cur.description is None:
            cur.close()
            return {"columns": [], "rows": [], "row_count": 0, "affected_rows": cur.rowcount}
        columns = [d[0] for d in cur.description]
        all_rows = cur.fetchall()
        truncated = len(all_rows) > max_rows
        data = [[_jsonable(v) for v in row.values()] for row in all_rows[:max_rows]]
        cur.close()
        return {"columns": columns, "rows": data, "row_count": len(data), "truncated": truncated}


def create_connection(cfg: ConnectionConfig) -> Database:
    if cfg.type == "dameng":
        return DamengDB(cfg)
    if cfg.type == "sqlserver":
        return SqlServerDB(cfg)
    raise ValueError(f"unsupported database type: {cfg.type!r}")
