/**
 * Structured, self-correctable tool errors.
 *
 * MCP spec (2025-06-18 / 2025-11-25) says input/execution failures must be
 * returned as tool results with isError:true (NOT protocol errors) so the
 * model can read the message and retry. We go one step further: every error
 * carries a machine-readable `code`, a `category`, a `recoverable` flag and a
 * human/LLM actionable `suggestion`. This follows the "deterministic error
 * handling" pattern used by production database MCP servers.
 *
 * SECURITY: driver errors frequently echo the connection string, host, user
 * or even the password. `redact()` scrubs every configured credential and
 * host from the message before it is returned to the model or written to the
 * audit log. We never log query results (they may contain PII).
 */

import { loadConnections } from './config.js';

export type ErrorCategory = 'policy' | 'validation' | 'timeout' | 'connection' | 'query' | 'config';

export interface StructuredError {
  /** Index signature lets the payload satisfy MCP's `structuredContent` record type. */
  [key: string]: unknown;
  ok: false;
  error: string;
  code: string;
  category: ErrorCategory;
  recoverable: boolean;
  suggestion?: string;
}

export interface StructuredErrorResult {
  content: { type: 'text'; text: string }[];
  isError: true;
  /** Machine-readable twin for clients that consume structuredContent. */
  structuredContent: StructuredError;
}

/* ------------------------------ redaction ------------------------------ */

/** Build the list of substrings that must never appear in an error message. */
function secretStrings(): string[] {
  const secrets: string[] = [];
  try {
    for (const c of loadConnections()) {
      if (c.password) secrets.push(c.password);
      if (c.user && c.user.length >= 3) secrets.push(c.user);
      if (c.host) secrets.push(c.host);
    }
  } catch {
    /* config may be invalid while reporting a config error — best effort */
  }
  // Longest first so a short credential can't leave a partial leak after a
  // shorter replacement (e.g. password "abc123" and user "abc").
  // Skip very short values (<4 chars): replacing every "x" in a message would
  // corrupt ordinary words ("exceeds" -> "e[REDACTED]ceeds"). Such short
  // credentials are still scrubbed by the URL / user:pass@ pattern rules below.
  return [...new Set(secrets)].filter((s) => s.length >= 4).sort((a, b) => b.length - a.length);
}

export function redact(message: string): string {
  let out = message;
  for (const secret of secretStrings()) {
    if (secret) out = out.split(secret).join('[REDACTED]');
  }
  // Dameng / generic URL connection strings: dm://user:pass@host:port?...
  out = out.replace(/[a-z][a-z0-9+.-]*:\/\/[^\s'")\]]+/gi, '[REDACTED_URL]');
  // user:password@host triples that survived (e.g. from a driver DSN echo).
  out = out.replace(/\b[^\s:@'"=]+:([^\s@'"=]+)@/g, '[REDACTED_CREDENTIALS]@');
  return out;
}

/* ---------------------------- classification ---------------------------- */

type ErrorDetails = Pick<StructuredError, 'code' | 'category' | 'recoverable' | 'suggestion'>;

function classify(e: unknown, fallbackCode: string): ErrorDetails {
  const name = (e as Error)?.name ?? '';
  const msg = (e as Error)?.message ?? String(e);

  if (name === 'QueryTimeoutError' || /timed?\s*out/i.test(msg)) {
    return {
      code: 'QUERY_TIMEOUT',
      category: 'timeout',
      recoverable: true,
      suggestion:
        'The query exceeded the configured time limit. Narrow the WHERE clause, add an index, or raise MULTIDB_QUERY_TIMEOUT_MS.',
    };
  }
  if (name === 'SqlPolicyError' || /SQL policy violation/i.test(msg)) {
    const readOnly = /read-only mode/i.test(msg);
    const multi = /multi-statement/i.test(msg);
    const param = /parameter count mismatch/i.test(msg);
    const length = /statement length|too long/i.test(msg);
    const ident = /invalid identifier/i.test(msg);
    if (param) {
      return {
        code: 'PARAM_COUNT_MISMATCH',
        category: 'validation',
        recoverable: true,
        suggestion: 'Supply exactly one `params` value per ? placeholder, or remove the placeholders.',
      };
    }
    if (length) {
      return {
        code: 'QUERY_TOO_LONG',
        category: 'validation',
        recoverable: true,
        suggestion: 'Split the statement or raise MULTIDB_MAX_QUERY_LENGTH.',
      };
    }
    if (ident) {
      return {
        code: 'INVALID_IDENTIFIER',
        category: 'validation',
        recoverable: true,
        suggestion: 'Identifiers must match [A-Za-z_#$][A-Za-z0-9_$#]*. Check the table/schema name.',
      };
    }
    if (multi) {
      return {
        code: 'MULTI_STATEMENT',
        category: 'policy',
        recoverable: true,
        suggestion: 'Send exactly one SQL statement per call, with at most one trailing semicolon.',
      };
    }
    if (readOnly) {
      return {
        code: 'READ_ONLY_VIOLATION',
        category: 'policy',
        recoverable: false,
        suggestion:
          'This connection is read-only. Rewriting the SQL will not help — an administrator must enable the matching write permission or use a writable connection.',
      };
    }
    return {
      code: 'WRITE_PERMISSION_DENIED',
      category: 'policy',
      recoverable: false,
      suggestion:
        'The matching write permission (allowInsert/allowUpdate/allowDelete/allowDdl) is disabled on this connection. Rewriting the SQL will not help.',
    };
  }
  if (/access denied|login failed|authentication|invalid credentials|er_access/i.test(msg)) {
    return {
      code: 'AUTH_FAILED',
      category: 'connection',
      recoverable: false,
      suggestion: 'Credentials were rejected. Verify the configured user/password; rewriting the SQL will not help.',
    };
  }
  if (
    /ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|connect\s*(timeout|failed|refused)|network|socket/i.test(msg) ||
    name === 'ConnectionError'
  ) {
    return {
      code: 'CONNECTION_FAILED',
      category: 'connection',
      recoverable: false,
      suggestion: 'The database is unreachable. Check host, port and network; rewriting the SQL will not help.',
    };
  }
  if (/unknown connection|multiple connections|not valid json|must be|configuration|missing host/i.test(msg)) {
    return {
      code: fallbackCode || 'CONFIG_ERROR',
      category: 'config',
      recoverable: false,
      suggestion: 'Check the connection configuration. Call list_connections to see available connection names.',
    };
  }
  return {
    code: fallbackCode || 'QUERY_FAILED',
    category: 'query',
    recoverable: true,
    suggestion:
      'The database rejected the statement. Check table/column names and SQL syntax for this database dialect, then retry.',
  };
}

/**
 * Build the pure structured-error payload (no MCP tool-result wrapper).
 * Reused by tool results, resource read bodies and audit records so the same
 * classification/redaction logic applies everywhere without structure mismatch.
 * `message` is human text; `rawError` is used only to classify (never emitted).
 */
export function buildStructuredError(
  message: string,
  rawError?: unknown,
  fallbackCode?: string
): StructuredError {
  const info = classify(rawError, fallbackCode ?? 'QUERY_FAILED');
  return { ok: false, ...info, error: redact(message) };
}

/**
 * Build an isError:true tool result from any thrown value.
 */
export function structuredError(
  message: string,
  rawError?: unknown,
  fallbackCode?: string
): StructuredErrorResult {
  const payload = buildStructuredError(message, rawError, fallbackCode);
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    isError: true,
    structuredContent: payload,
  };
}
