"""End-to-end smoke test: drive multidb-mcp over stdio JSON-RPC against a real
Dameng database (192.168.0.30) and assert both positive and negative paths.

Run:
    python tests/stdio_smoke.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

VENV_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".venv", "Scripts", "python.exe")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ENV = dict(os.environ)
ENV["PYTHONPATH"] = os.path.join(ROOT, "src")
ENV.update({
    "DB_TYPE": "dameng",
    "DB_HOST": "192.168.0.30",
    "DB_PORT": "5236",
    "DB_USER": "SYSDBA",
    "DB_PASSWORD": "Gschina0601",
    "DB_SCHEMA": "SYSDBA",
})


def main() -> int:
    proc = subprocess.Popen(
        [VENV_PY, "-m", "multidb_mcp.server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=ENV, text=True, encoding="utf-8", bufsize=1,
    )

    _next_id = [0]

    def send(obj: dict) -> int:
        _next_id[0] += 1
        obj = dict(obj, id=_next_id[0])
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()
        return obj["id"]

    def read(expected_id: int) -> dict:
        # MCP stdio is line-delimited JSON-RPC. The server may emit
        # notifications (logs, progress) between requests and responses, so
        # skip any message whose id does not match the expected response.
        while True:
            line = proc.stdout.readline()
            if not line:
                err = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"server closed stdout; stderr: {err}")
            msg = json.loads(line)
            if msg.get("id") == expected_id and ("result" in msg or "error" in msg):
                return msg

    failures = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {label}" + (f" | {detail}" if detail else ""))
        if not ok:
            failures.append(label)

    try:
        rid = send({"jsonrpc": "2.0", "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "smoke-test", "version": "0.1"},
        }})
        init = read(rid)
        check("initialize", init.get("result", {}).get("serverInfo", {}).get("name") == "multidb-mcp",
              str(init.get("result", {}).get("serverInfo")))

        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()

        rid = send({"jsonrpc": "2.0", "method": "tools/list", "params": {}})
        tools = read(rid)
        names = [t["name"] for t in tools.get("result", {}).get("tools", [])]
        expected = {"list_connections", "test_connection", "list_tables", "describe_table", "execute_sql"}
        check("tools/list registers 5 tools", expected.issubset(set(names)), ",".join(names))

        rid = send({"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": "test_connection", "arguments": {}}})
        r = read(rid)
        payload = r.get("result", {})
        text = payload.get("content", [{}])[0].get("text", "")
        info = json.loads(text)
        check("test_connection -> DM8 online",
              info.get("type") == "dameng" and "DM Database Server" in info.get("version", ""),
              info.get("version", ""))

        rid = send({"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": "list_tables", "arguments": {}}})
        r = read(rid)
        tables_payload = json.loads(r["result"]["content"][0]["text"])
        tables = tables_payload.get("tables", [])
        check("list_tables returns tables", len(tables) >= 1, f"tables={tables}")

        if tables:
            t = tables[0]
            rid = send({"jsonrpc": "2.0", "method": "tools/call", "params": {
                "name": "describe_table", "arguments": {"table": t}}})
            r = read(rid)
            raw_text = r["result"]["content"][0]["text"]
            if not raw_text.strip().startswith("{"):
                print("RAW describe_table TEXT:", repr(raw_text[:300]))
            desc = json.loads(raw_text)
            check("describe_table returns columns",
                  len(desc.get("columns", [])) >= 0 and desc.get("table") == t,
                  f"table={t}, columns={len(desc.get('columns', []))}")

        rid = send({"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": "execute_sql", "arguments": {"sql": "SELECT COUNT(*) AS CNT FROM USER_TABLES"}}})
        r = read(rid)
        res = json.loads(r["result"]["content"][0]["text"])
        ok_select = res.get("columns") == ["CNT"] and res.get("rows") and res.get("row_count", 0) >= 1
        check("execute_sql SELECT works", ok_select, json.dumps(res, ensure_ascii=False)[:120])

        rid = send({"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": "execute_sql", "arguments": {"sql": "DELETE FROM DUAL"}}})
        r = read(rid)
        res = json.loads(r["result"]["content"][0]["text"])
        check("execute_sql blocks DML at readonly level", "error" in res,
              res.get("error", "")[:80])

        rid = send({"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": "execute_sql", "arguments": {"sql": "SELECT 1; SELECT 2"}}})
        r = read(rid)
        res = json.loads(r["result"]["content"][0]["text"])
        check("execute_sql blocks multi-statement", "error" in res,
              res.get("error", "")[:80])

        rid = send({"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": "execute_sql", "arguments": {"sql": "SELECT 1 WHERE 1=1 -- trailing"}}})
        r = read(rid)
        res = json.loads(r["result"]["content"][0]["text"])
        check("execute_sql blocks comment injection", "error" in res,
              res.get("error", "")[:80])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print()
    if failures:
        print(f"SMOKE TEST FAILED: {failures}")
        return 1
    print("SMOKE TEST PASSED: all checks green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
