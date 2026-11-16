"""Unit tests for multidb-mcp: SQL safety policy, config parsing, connection
routing, and SQL Server SQL construction (mocked, no live DB required).

Run:
    python tests/test_unit.py
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from multidb_mcp.config import ConnectionConfig, load_connections  # noqa: E402
from multidb_mcp.db import SqlServerDB  # noqa: E402
from multidb_mcp.security import SqlPolicyError, check_identifier, check_sql  # noqa: E402


class SecurityPolicyTest(unittest.TestCase):
    def test_select_allowed_at_readonly(self):
        check_sql("SELECT * FROM users WHERE id = 1", "readonly")

    def test_with_cte_allowed_at_readonly(self):
        check_sql("WITH t AS (SELECT 1) SELECT * FROM t", "readonly")

    def test_dml_blocked_at_readonly(self):
        with self.assertRaises(SqlPolicyError):
            check_sql("DELETE FROM users", "readonly")

    def test_dml_allowed_at_dml(self):
        check_sql("INSERT INTO users VALUES (1)", "dml")
        check_sql("UPDATE users SET a = 1", "dml")

    def test_ddl_blocked_at_dml(self):
        with self.assertRaises(SqlPolicyError):
            check_sql("DROP TABLE users", "dml")

    def test_ddl_allowed_at_ddl(self):
        check_sql("DROP TABLE users", "ddl")
        check_sql("CREATE TABLE t (id INT)", "ddl")

    def test_multi_statement_blocked_at_every_level(self):
        for level in ("readonly", "dml", "ddl", "full"):
            with self.assertRaises(SqlPolicyError, msg=f"level={level}") as ctx:
                check_sql("SELECT 1; DROP TABLE users", level)
            self.assertIn("multi-statement", str(ctx.exception))

    def test_trailing_semicolon_ok(self):
        check_sql("SELECT 1;", "readonly")

    def test_comment_blocked(self):
        for level in ("readonly", "dml", "ddl", "full"):
            with self.assertRaises(SqlPolicyError, msg=f"level={level}") as ctx:
                check_sql("SELECT 1 -- hidden", level)
            self.assertIn("comment", str(ctx.exception))

    def test_block_comment_blocked(self):
        with self.assertRaises(SqlPolicyError):
            check_sql("SELECT 1 /* hidden */", "full")

    def test_string_content_not_misdetected(self):
        # Keywords inside string literals must not trigger the policy
        check_sql("SELECT 'a;b' AS x, '--' AS y, 'DROP TABLE x' AS z", "readonly")
        check_sql("INSERT INTO t VALUES ('DELETE FROM x')", "dml")

    def test_exec_and_grant_blocked_at_all_levels(self):
        for stmt in ("EXEC sp_who", "CALL p()", "GRANT SELECT ON t TO u",
                     "REVOKE SELECT ON t FROM u", "SET SCHEMA x"):
            with self.assertRaises(SqlPolicyError, msg=stmt):
                check_sql(stmt, "full")

    def test_identifier_validation(self):
        check_identifier("##HISTOGRAMS_TABLE")
        check_identifier("T_AB$1")
        check_identifier("dbo")
        for bad in ("t; DROP", "a b", "a'b", "", "a-b", "1;2"):
            with self.assertRaises(SqlPolicyError, msg=bad):
                check_identifier(bad)


class ConfigTest(unittest.TestCase):
    ENV_KEYS = ("DB_CONNECTIONS", "DB_TYPE", "DB_HOST", "DB_PORT", "DB_USER",
                "DB_PASSWORD", "DB_SCHEMA", "DB_DATABASE", "DB_SQL_ACCESS",
                "DB_MAX_ROWS", "DB_DESCRIPTION")

    def _env(self, **kv):
        return mock.patch.dict(os.environ, kv, clear=True)

    def test_single_connection_shorthand(self):
        with self._env(DB_TYPE="dameng", DB_HOST="192.168.0.30",
                       DB_USER="SYSDBA", DB_PASSWORD="pw", DB_SCHEMA="SYSDBA"):
            conns = load_connections()
        self.assertEqual(len(conns), 1)
        c = conns[0]
        self.assertEqual((c.name, c.type, c.host, c.port), ("default", "dameng", "192.168.0.30", 5236))
        self.assertEqual(c.schema, "SYSDBA")
        self.assertEqual(c.sql_access, "readonly")

    def test_sqlserver_default_port(self):
        with self._env(DB_TYPE="sqlserver", DB_HOST="10.0.0.5",
                       DB_USER="sa", DB_PASSWORD="pw", DB_DATABASE="HBDB"):
            conns = load_connections()
        self.assertEqual(conns[0].port, 1433)
        self.assertEqual(conns[0].database, "HBDB")

    def test_multi_connection_json(self):
        payload = (
            '[{"name":"dm","type":"dameng","host":"192.168.0.30","user":"SYSDBA",'
            '"password":"pw","schema":"SYSDBA","description":"开发"},'
            '{"name":"mssql","type":"sqlserver","host":"10.0.0.5","user":"sa",'
            '"password":"pw","database":"HBDB","sql_access":"dml"}]'
        )
        with self._env(DB_CONNECTIONS=payload):
            conns = load_connections()
        self.assertEqual(len(conns), 2)
        self.assertEqual(conns[0].name, "dm")
        self.assertEqual(conns[1].sql_access, "dml")
        self.assertEqual(conns[1].type, "sqlserver")

    def test_bad_json_rejected(self):
        with self._env(DB_CONNECTIONS="not json"):
            with self.assertRaises(ValueError):
                load_connections()

    def test_bad_type_rejected(self):
        with self._env(DB_CONNECTIONS='[{"name":"x","type":"oracle","host":"h"}]'):
            with self.assertRaises(ValueError):
                load_connections()

    def test_bad_access_rejected(self):
        with self._env(DB_CONNECTIONS='[{"name":"x","type":"dameng","host":"h","sql_access":"root"}]'):
            with self.assertRaises(ValueError):
                load_connections()

    def test_missing_host_rejected(self):
        with self._env(DB_CONNECTIONS='[{"name":"x","type":"dameng"}]'):
            with self.assertRaises(ValueError):
                load_connections()

    def test_safe_summary_hides_password(self):
        c = ConnectionConfig(name="x", type="dameng", host="h", port=5236,
                             user="u", password="secret", schema="s")
        summary = c.safe_summary()
        self.assertNotIn("password", summary)
        self.assertNotIn("secret", str(summary))


class FakeCursor:
    def __init__(self):
        self.calls = []
        self.description = None
        self.rowcount = 0

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return []

    def fetchone(self):
        return None

    def close(self):
        pass


class FakeConn:
    def __init__(self):
        self.cursor_obj = FakeCursor()

    def cursor(self):
        return self.cursor_obj

    def close(self):
        pass


class SqlServerSQLTest(unittest.TestCase):
    """Verify the SQL Server queries are constructed correctly (mocked)."""

    def _db(self):
        cfg = ConnectionConfig(name="mssql", type="sqlserver", host="10.0.0.5",
                               port=1433, user="sa", password="pw", database="HBDB")
        db = SqlServerDB(cfg)
        db._conn = FakeConn()
        return db

    def test_list_tables_with_schema(self):
        db = self._db()
        db.list_tables("dbo")
        sql, params = db._conn.cursor_obj.calls[0]
        self.assertIn("INFORMATION_SCHEMA.TABLES", sql)
        self.assertEqual(params, ("dbo",))

    def test_list_tables_default(self):
        db = self._db()
        db.list_tables()
        sql, _ = db._conn.cursor_obj.calls[0]
        self.assertIn("BASE TABLE", sql)

    def test_describe_table_sql(self):
        db = self._db()
        db.describe_table("USERS", "dbo")
        sql, params = db._conn.cursor_obj.calls[0]
        self.assertIn("INFORMATION_SCHEMA.COLUMNS", sql)
        self.assertEqual(params, ("dbo", "USERS"))

    def test_server_info_sql(self):
        db = self._db()
        db.server_info()
        sql, _ = db._conn.cursor_obj.calls[0]
        self.assertIn("@@VERSION", sql)


class RoutingTest(unittest.TestCase):
    """Multi-connection routing: explicit selection required, no silent default."""

    def _catalog(self, names):
        from multidb_mcp import server
        server._catalog = [
            ConnectionConfig(name=n, type="dameng", host="h", port=5236,
                             user="u", password="p", schema=n)
            for n in names
        ]

    def test_single_connection_auto_selected(self):
        from multidb_mcp import server
        self._catalog(["only"])
        cfg = server._resolve("")
        self.assertEqual(cfg.name, "only")

    def test_multi_connection_requires_explicit_name(self):
        from multidb_mcp import server
        self._catalog(["dev", "prod"])
        with self.assertRaises(ValueError) as ctx:
            server._resolve("")
        msg = str(ctx.exception)
        self.assertIn("dev", msg)
        self.assertIn("prod", msg)
        self.assertIn("connection", msg.lower())

    def test_unknown_connection_lists_catalog(self):
        from multidb_mcp import server
        self._catalog(["dev", "prod"])
        with self.assertRaises(ValueError) as ctx:
            server._resolve("nope")
        msg = str(ctx.exception)
        self.assertIn("dev", msg)
        self.assertIn("prod", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
