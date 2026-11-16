/**
 * Result-set hardening applied at the MCP tool boundary, just before rows
 * leave the server. Two defences, both from production database-MCP practice:
 *
 *  1. Column masking — values in columns whose name matches a configured
 *     regex are masked (fixed / null / partial). Applies to EVERY query shape,
 *     including SELECT *, so a model cannot dodge a mask with an alias that
 *     keeps the original column name in the result set.
 *  2. Byte cap — even when row count is capped, a single BLOB / long text
 *     column can flood the model context. Cap the serialized result size and
 *     drop whole rows past the budget, flagging it for the caller.
 *
 * Both are pure functions so they can be unit-tested without a database.
 */

import type { MaskingRule } from './config.js';
import type { QueryResult } from './db.js';

export interface MaskOutcome {
  result: QueryResult;
  /** Column names that matched at least one rule and were masked. */
  maskedColumns: string[];
}

function maskValue(value: unknown, rule: MaskingRule): unknown {
  if (value === null || value === undefined) return value;
  if (rule.strategy === 'null') return null;
  if (rule.strategy === 'fixed') return rule.value ?? '***';

  // partial: keep the last N characters visible, mask everything before them.
  const text = String(value);
  const keep = Math.max(0, rule.keepLast ?? 4);
  if (text.length <= keep) return '*'.repeat(text.length); // short values fully masked
  return '*'.repeat(text.length - keep) + text.slice(-keep);
}

/**
 * Apply configured masking rules to every row. Rules are tested against the
 * ORIGINAL column name (case-insensitive). Compiled here rather than cached
 * because rule sets are small and config is loaded once at startup.
 */
export function applyMasking(result: QueryResult, rules: MaskingRule[]): MaskOutcome {
  if (!rules.length || result.rows.length === 0) {
    return { result, maskedColumns: [] };
  }

  const compiled = rules.map((r) => ({ ...r, re: new RegExp(r.column, 'i') }));
  const maskedColumns = new Set<string>();

  const rows = result.rows.map((row) => {
    let changed = false;
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(row)) {
      const rule = compiled.find((r) => r.re.test(key));
      if (rule) {
        out[key] = maskValue(value, rule);
        maskedColumns.add(key);
        changed = true;
      } else {
        out[key] = value;
      }
    }
    return changed ? out : row;
  });

  return { result: { ...result, rows }, maskedColumns: [...maskedColumns] };
}

export interface ByteCapOutcome {
  rows: Record<string, unknown>[];
  truncatedByBytes: boolean;
  bytes: number;
}

/**
 * Keep as many leading rows as fit in `maxBytes` (UTF-8 serialized size).
 * Dropping whole rows (rather than clipping a cell) keeps every returned row
 * a valid, complete record. `maxBytes <= 0` disables the cap.
 */
export function capResultBytes(rows: Record<string, unknown>[], maxBytes: number): ByteCapOutcome {
  if (maxBytes <= 0) return { rows, truncatedByBytes: false, bytes: 0 };

  let bytes = 0;
  const kept: Record<string, unknown>[] = [];
  for (const row of rows) {
    const size = Buffer.byteLength(JSON.stringify(row), 'utf8');
    if (bytes + size > maxBytes) break;
    bytes += size;
    kept.push(row);
  }
  return { rows: kept, truncatedByBytes: kept.length < rows.length, bytes };
}
