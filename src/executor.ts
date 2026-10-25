import type {
  AuditEvent,
  ClientLike,
  ColumnInfo,
  ExecutorOptions,
  GuardPolicy,
  PoolLike,
  RunOptions,
  RunResult,
  ValidationResult,
} from "./types.js";
import { validate } from "./validate.js";

const IDENT = /^[a-z_][a-z0-9_$]*$/;
const SETTING = /^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/;

export const limits = {
  maxRows: (p: GuardPolicy) => Math.max(1, Math.min(p.maxRows ?? 500, 10_000)),
  timeoutMs: (p: GuardPolicy) => Math.max(100, Math.min(p.timeoutMs ?? 3000, 60_000)),
};

/** Throws on a policy that could inject into the setup statements. */
export function assertSafePolicy(policy: GuardPolicy): void {
  if (!Array.isArray(policy.allowedRelations) || policy.allowedRelations.length === 0) {
    throw new Error("pg-guard-sql: policy.allowedRelations must list at least one relation");
  }
  if (policy.role !== undefined && !IDENT.test(policy.role)) throw new Error("pg-guard-sql: invalid role name");
  if (policy.schema !== undefined && !IDENT.test(policy.schema)) throw new Error("pg-guard-sql: invalid schema name");
  for (const k of [...Object.keys(policy.settings ?? {}), ...(policy.requiredSettings ?? [])]) {
    if (!SETTING.test(k)) throw new Error(`pg-guard-sql: invalid setting name "${k}" (use prefix.name, e.g. app.user_id)`);
  }
}

export interface GuardedExecutor {
  readonly policy: GuardPolicy;
  /** AST validation only; never touches the database. */
  validate(sql: string): Promise<ValidationResult>;
  /** Validate, then execute in a read-only, time-boxed, role- and RLS-scoped transaction that is always rolled back. */
  run(sql: string, opts?: RunOptions): Promise<RunResult>;
  /** Columns of an allowlisted relation as seen by the guarded role (column grants apply). */
  describe(relation: string, opts?: RunOptions): Promise<ColumnInfo[]>;
}

/**
 * Create an executor for untrusted SQL with defense in depth:
 *  1. AST check: single SELECT, relation + function allowlists          -> validate()
 *  2. READ ONLY transaction, always rolled back                          -> BEGIN READ ONLY
 *  3. statement_timeout / lock_timeout / idle timeout                    -> SET LOCAL
 *  4. least-privilege role (RLS applies to it)                           -> SET LOCAL ROLE
 *  5. per-transaction settings read by RLS policies                      -> set_config(..., true)
 *  6. hard row cap                                                       -> outer LIMIT
 *  7. audit callback for every attempt (blocked, failed or ok)
 */
export function createGuardedExecutor(pool: PoolLike, policy: GuardPolicy, options: ExecutorOptions = {}): GuardedExecutor {
  assertSafePolicy(policy);
  const maxRows = limits.maxRows(policy);
  const timeoutMs = limits.timeoutMs(policy);
  const schema = policy.schema ?? "public";

  const audit = async (e: AuditEvent) => {
    try {
      await options.onAudit?.(e);
    } catch {
      /* audit must never break the request */
    }
  };

  const resolveSettings = (opts?: RunOptions): Record<string, string> => {
    const settings = { ...(policy.settings ?? {}), ...(opts?.settings ?? {}) };
    for (const k of Object.keys(settings)) {
      if (!SETTING.test(k)) throw new Error(`pg-guard-sql: invalid setting name "${k}"`);
    }
    for (const k of policy.requiredSettings ?? []) {
      if (!settings[k]) throw new Error(`pg-guard-sql: required setting "${k}" is not set`);
    }
    return settings;
  };

  /** Open the guarded transaction, run `fn`, always roll back. */
  async function inGuardedTx<T>(settings: Record<string, string>, fn: (c: ClientLike) => Promise<T>): Promise<T> {
    const client = await pool.connect();
    let broken = false;
    try {
      await client.query("BEGIN READ ONLY");
      await client.query(`SET LOCAL statement_timeout = ${timeoutMs}`);
      await client.query(`SET LOCAL lock_timeout = ${timeoutMs}`);
      await client.query("SET LOCAL idle_in_transaction_session_timeout = 10000");
      await client.query(`SET LOCAL search_path = ${schema}`);
      if (policy.role) await client.query(`SET LOCAL ROLE ${policy.role}`);
      for (const [k, v] of Object.entries(settings)) {
        await client.query("SELECT set_config($1, $2, true)", [k, v]);
      }
      return await fn(client);
    } finally {
      try {
        await client.query("ROLLBACK");
      } catch {
        broken = true;
      }
      client.release(broken);
    }
  }

  return {
    policy,
    validate: (sql) => validate(sql, policy),

    async run(sql, opts) {
      const started = Date.now();
      let settings: Record<string, string>;
      try {
        settings = resolveSettings(opts);
      } catch (e) {
        const reason = (e as Error).message;
        await audit({ sql, status: "error", settings: {}, reason, durationMs: Date.now() - started });
        return { ok: false, status: "error", reason, durationMs: Date.now() - started };
      }

      const v = await validate(sql, policy);
      if (!v.allowed) {
        const durationMs = Date.now() - started;
        const reason = v.reasons.join("; ");
        await audit({ sql, status: "blocked", settings, code: v.code, reason, durationMs });
        return { ok: false, status: "blocked", code: v.code, reason, reasons: v.reasons, durationMs };
      }

      // Newline before ")" so a trailing "-- comment" in the inner query cannot swallow it.
      const executedSql = `SELECT * FROM (\n${v.sql}\n) AS pg_guard_q LIMIT ${maxRows + 1}`;
      try {
        const res = await inGuardedTx(settings, (c) => c.query(executedSql));
        const truncated = res.rows.length > maxRows;
        const rows = truncated ? res.rows.slice(0, maxRows) : res.rows;
        const columns = res.fields?.map((f) => f.name) ?? Object.keys(rows[0] ?? {});
        const durationMs = Date.now() - started;
        await audit({ sql, status: "ok", settings, rowCount: rows.length, durationMs });
        return { ok: true, columns, rows, rowCount: rows.length, truncated, durationMs, executedSql };
      } catch (e) {
        const durationMs = Date.now() - started;
        const reason = (e as Error).message;
        await audit({ sql, status: "error", settings, reason, durationMs });
        return { ok: false, status: "error", reason, durationMs };
      }
    },

    async describe(relation, opts) {
      const name = relation.includes(".") && relation.startsWith(`${schema}.`) ? relation.slice(schema.length + 1) : relation;
      const allowed = policy.allowedRelations.some((r) => r === name || r === `${schema}.${name}`);
      if (!allowed) throw new Error(`Relation "${relation}" is not in the allowlist`);
      const settings = resolveSettings(opts);
      // Runs as the guarded role: information_schema.columns only lists columns that role may read.
      const res = await inGuardedTx(settings, (c) =>
        c.query(
          `SELECT c.column_name AS name,
                  CASE WHEN c.data_type = 'USER-DEFINED' THEN c.udt_name ELSE c.data_type END AS type,
                  c.is_nullable = 'YES' AS nullable,
                  pg_catalog.col_description(format('%I.%I', c.table_schema, c.table_name)::regclass, c.ordinal_position) AS description
             FROM information_schema.columns c
            WHERE c.table_schema = $1 AND c.table_name = $2
            ORDER BY c.ordinal_position`,
          [schema, name],
        ),
      );
      return res.rows as unknown as ColumnInfo[];
    },
  };
}
