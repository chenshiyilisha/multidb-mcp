"""SQL safety checks for multidb-mcp.

Strategy (kept deliberately simple and predictable):
- Strip string literals and comments first, then inspect the remaining SQL.
- Reject multi-statement input (a ';' anywhere except as trailing whitespace).
- Reject comment-injection patterns in the stripped SQL (-- , /* ).
- Enforce statement-verb whitelists per sql_access level:
    readonly: SELECT / WITH / EXPLAIN / SHOW / DESCRIBE / DESC
    dml:      readonly + INSERT / UPDATE / DELETE / MERGE
    ddl:      dml + CREATE / ALTER / DROP / TRUNCATE / RENAME / COMMENT
    full:     only multi-statement / comment-injection checks apply
- Always blocked (any level): EXEC / EXECUTE / CALL / GRANT / REVOKE /
  xp_ / sp_ style procedure calls and session-state commands (SET, USE).
- Identifier format check: [A-Za-z0-9_$#]+ (SQL Server temp-table
  prefixes #/## and Dameng $ are allowed).
"""
from __future__ import annotations

import re

_STRING_RE = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")
_IDENT_RE = re.compile(r"^[A-Za-z0-9_$#]+$")

READONLY_VERBS = {"select", "with", "explain", "show", "describe", "desc"}
DML_VERBS = READONLY_VERBS | {"insert", "update", "delete", "merge"}
DDL_VERBS = DML_VERBS | {"create", "alter", "drop", "truncate", "rename", "comment"}

# Never allowed at any access level
ALWAYS_BLOCKED_PREFIXES = {
    "exec", "execute", "call", "grant", "revoke", "set", "use", "declare",
}
ALWAYS_BLOCKED_PREFIXES_2 = {"xp_", "sp_"}


class SqlPolicyError(Exception):
    """Raised when a SQL statement violates the safety policy."""


def _strip_literals(sql: str) -> str:
    """Remove string literals and comments so keyword scanning is safe."""
    stripped = _STRING_RE.sub("''", sql)
    stripped = _LINE_COMMENT_RE.sub(" ", stripped)
    stripped = _BLOCK_COMMENT_RE.sub(" ", stripped)
    return stripped


def check_identifier(name: str) -> str:
    """Validate an identifier (table/schema/column name) format.

    Character-set whitelist only: letters, digits, underscore, $ and #
    (SQL Server temp-table prefixes and Dameng $ names are allowed). No
    spaces, quotes or punctuation can pass, which rules out injection
    through identifier arguments.
    """
    if not name or not _IDENT_RE.match(name):
        raise SqlPolicyError(
            f"invalid identifier: {name!r} "
            "(must contain only letters, digits, _, $, #)"
        )
    return name


def check_sql(sql: str, access: str = "readonly") -> str:
    """Validate one SQL statement against the access level. Returns normalized SQL."""
    if not sql or not sql.strip():
        raise SqlPolicyError("SQL statement is empty")

    access = (access or "readonly").lower()
    if access not in ("readonly", "dml", "ddl", "full"):
        raise SqlPolicyError(f"unknown access level: {access!r}")

    stripped = _strip_literals(sql).strip()

    # Comment injection: comments are never needed in LLM-generated SQL, so
    # any comment marker surviving string-literal stripping is an injection
    # attempt. (Checked before stripping comments, which would hide them.)
    no_comments_check = _STRING_RE.sub("''", sql)
    if "--" in no_comments_check or "/*" in no_comments_check:
        raise SqlPolicyError("SQL comments are not allowed")

    # Multi-statement injection: any ';' that is not trailing
    body = stripped.rstrip().rstrip(";").strip()
    if ";" in body:
        raise SqlPolicyError(
            "multi-statement SQL is not allowed (only one statement per call)"
        )

    # Comment injection in the cleaned SQL
    if "--" in body or "/*" in body:
        raise SqlPolicyError("SQL comments are not allowed")

    verb = body.split(None, 1)[0].lower().strip("(")
    # Handle leading parenthesized SELECT: "(SELECT ...)"
    if verb == "":
        raise SqlPolicyError("SQL statement is empty after cleaning")

    if verb in ALWAYS_BLOCKED_PREFIXES:
        raise SqlPolicyError(
            f"statement type '{verb}' is blocked at all access levels"
        )
    if verb.startswith(tuple(ALWAYS_BLOCKED_PREFIXES_2)):
        raise SqlPolicyError(
            f"stored-procedure style call '{verb}' is blocked at all access levels"
        )

    allowed = {"full": None}.get(access)
    if allowed is None:
        allowed_set = {"readonly": READONLY_VERBS, "dml": DML_VERBS, "ddl": DDL_VERBS}[access]
        if verb not in allowed_set:
            raise SqlPolicyError(
                f"statement type '{verb}' is not allowed at '{access}' level "
                f"(allowed: {', '.join(sorted(allowed_set))})"
            )
    return sql.strip()
