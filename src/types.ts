/**
 * pg-guard-sql: run untrusted (e.g. LLM-written) SQL on Postgres with defense in depth.
 */

export interface GuardPolicy {
  /**
   * Relations (tables or views) a query may read, exactly as named in the catalog
   * (normally lower case). Unqualified, or qualified with `schema`.
   */
  allowedRelations: string[];
  /** Optional human/LLM-facing descriptions per relation, shown by `list_allowed_tables`. */
  descriptions?: Record<string, string>;
  /** The one schema queries run in (`search_path`). Default `public`. */
  schema?: string;
  /** Functions a query may call. Replaces the default list when given. */
  allowedFunctions?: string[];
  /** Functions added on top of `allowedFunctions` (or the defaults). */
  extraFunctions?: string[];
  /** Max characters of SQL accepted. Default 4000. */
  maxSqlLength?: number;
  /** Allow WITH RECURSIVE. Default false. */
  allowRecursiveCte?: boolean;
  /** Rows returned at most; the query is wrapped in an outer LIMIT. Default 500, max 10000. */
  maxRows?: number;
  /** statement_timeout in ms. Default 3000, max 60000. */
  timeoutMs?: number;
  /** NOLOGIN read-only role to `SET LOCAL ROLE` into for every query. Strongly recommended. */
  role?: string;
  /** Transaction-local settings, e.g. `{ "app.user_id": "alice" }`, read by RLS policies. */
  settings?: Record<string, string>;
  /** Settings that must be non-empty at run time, or the query is refused (fail closed). */
  requiredSettings?: string[];
}

export type GuardErrorCode =
  | "EMPTY"
  | "TOO_LONG"
  | "FORBIDDEN_CHAR"
  | "PARSE_ERROR"
  | "MULTIPLE_STATEMENTS"
  | "NOT_SELECT"
  | "SELECT_INTO"
  | "LOCKING_CLAUSE"
  | "FORBIDDEN_RELATION"
  | "FORBIDDEN_SCHEMA"
  | "FORBIDDEN_FUNCTION"
  | "FORBIDDEN_NODE"
  | "FORBIDDEN_CAST"
  | "RECURSIVE_CTE"
  | "DATA_MODIFYING_CTE";

export interface Violation {
  code: GuardErrorCode;
  reason: string;
}

export type ValidationResult =
  | {
      allowed: true;
      /** The original statement, trimmed and without trailing semicolons. */
      sql: string;
      relations: string[];
      functions: string[];
      reasons: [];
    }
  | {
      allowed: false;
      /** Code of the first violation. */
      code: GuardErrorCode;
      /** Every violation found, in order, as readable sentences (good for an LLM to repair its query). */
      reasons: string[];
      violations: Violation[];
    };

/** Minimal client/pool shapes so callers can pass a `pg.Pool` (or anything compatible). */
export interface QueryResultLike {
  rows: Record<string, unknown>[];
  fields?: { name: string }[];
}
export interface ClientLike {
  query(text: string, params?: unknown[]): Promise<QueryResultLike>;
  release(err?: Error | boolean): void;
}
export interface PoolLike {
  connect(): Promise<ClientLike>;
}

export interface AuditEvent {
  sql: string;
  status: "ok" | "blocked" | "error";
  /** The transaction-local settings used (e.g. the RLS user). */
  settings: Record<string, string>;
  code?: GuardErrorCode;
  reason?: string;
  rowCount?: number;
  durationMs: number;
}

export interface ExecutorOptions {
  /** Called for every attempt (blocked, failed or ok). Errors thrown here are swallowed. */
  onAudit?: (event: AuditEvent) => void | Promise<void>;
}

export interface RunOptions {
  /** Per-call settings merged over `policy.settings`, e.g. the signed-in user's id. */
  settings?: Record<string, string>;
}

export type RunResult =
  | {
      ok: true;
      columns: string[];
      rows: Record<string, unknown>[];
      rowCount: number;
      truncated: boolean;
      durationMs: number;
      executedSql: string;
    }
  | {
      ok: false;
      status: "blocked" | "error";
      code?: GuardErrorCode;
      reason: string;
      reasons?: string[];
      durationMs: number;
    };

export interface ColumnInfo {
  name: string;
  type: string;
  nullable: boolean;
  description: string | null;
}
