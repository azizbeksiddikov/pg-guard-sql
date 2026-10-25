import pg from "pg";
import Cursor from "pg-cursor";
import { to as copyTo } from "pg-copy-streams";
import { parse } from "libpg-query";
import { createGuardedExecutor } from "../../src/executor.js";
import type { GuardPolicy } from "../../src/types.js";
import { ATTACKS, type Attack } from "./attacks.js";

export const SUITE_POLICY: GuardPolicy = {
  allowedRelations: ["v_orders", "products"],
  role: "ai_reader",
  requiredSettings: ["app.user_id"],
  settings: { "app.user_id": "alice" },
  maxRows: 500,
  timeoutMs: 2000,
};
const SLOW_MS = SUITE_POLICY.timeoutMs! + 2500;

export type Verdict = "blocked" | "contained" | "stopped" | "LEAK" | "WRITE" | "SLOW" | "OVER_CAP";
export const SAFE: Verdict[] = ["blocked", "contained", "stopped"];

export interface LayerResult {
  verdict: Verdict;
  detail: string;
  ms: number;
}
export interface AttackResult {
  attack: Attack;
  /** Full pg-guard-sql: validator + DB layers. */
  guarded: LayerResult & { code?: string };
  /** Validator removed: same transaction setup (READ ONLY, role, RLS setting, timeout), raw SQL. */
  dbOnly: LayerResult;
}

async function snapshot(admin: pg.Pool): Promise<string> {
  const r = await admin.query(`SELECT
    (SELECT count(*) FROM orders) o, (SELECT coalesce(sum(total),0) FROM orders) t,
    (SELECT string_agg(note, '|' ORDER BY id) FROM orders) n,
    (SELECT count(*) FROM users) u, (SELECT count(*) FROM api_keys) k,
    (SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace) c,
    (SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace) f`);
  return JSON.stringify(r.rows[0]);
}

const leaks = (rows: unknown) => /SECRET/.test(JSON.stringify(rows, (_k, v) => (typeof v === "bigint" ? String(v) : v)));
const firstLine = (s: string) => s.split("\n")[0].slice(0, 90);

async function statementTypes(sql: string): Promise<string[]> {
  try {
    const t = (await parse(sql)) as { stmts?: { stmt: Record<string, unknown> }[] };
    return (t.stmts ?? []).map((s) => Object.keys(s.stmt)[0]);
  } catch {
    return [];
  }
}

/** COPY ... TO STDOUT streams data; capture it as text so it can be checked for leaks. */
async function readCopy(client: pg.Client, sql: string): Promise<unknown[]> {
  const stream = client.query(copyTo(sql));
  let out = "";
  for await (const chunk of stream) {
    out += chunk.toString();
    if (out.length > 1_000_000) break;
  }
  return out ? [{ copy: out }] : [];
}

/** Run the attack with every DB layer but no validator, on a fresh connection that is then discarded. */
async function runDbOnly(appUrl: string, sql: string): Promise<{ rows: unknown[]; error?: string; ms: number }> {
  const client = new pg.Client({ connectionString: appUrl });
  await client.connect();
  client.on("error", () => {});
  const started = Date.now();
  try {
    await client.query("BEGIN READ ONLY");
    await client.query(`SET LOCAL statement_timeout = ${SUITE_POLICY.timeoutMs}`);
    await client.query(`SET LOCAL ROLE ${SUITE_POLICY.role}`);
    await client.query("SELECT set_config('app.user_id', 'alice', true)");
    let rows: unknown[] = [];
    const types = await statementTypes(sql);
    if (types.length === 1 && types[0] === "CopyStmt" && /to\s+stdout/i.test(sql)) {
      rows = await readCopy(client, sql);
    } else if (types.length === 1) {
      // Single statement: fetch at most maxRows+1 so a huge result cannot exhaust test memory.
      const cur = client.query(new Cursor(sql));
      rows = await cur.read(SUITE_POLICY.maxRows! + 1);
      await cur.close();
    } else {
      // Several statements (or unparsable): simple protocol, exactly like a naive executor would.
      const res = (await client.query(sql)) as unknown as pg.QueryResult | pg.QueryResult[];
      rows = (Array.isArray(res) ? res : [res]).flatMap((r) => r.rows ?? []);
    }
    return { rows, ms: Date.now() - started };
  } catch (e) {
    return { rows: [], error: (e as Error).message, ms: Date.now() - started };
  } finally {
    await client.query("ROLLBACK").catch(() => {});
    await client.end().catch(() => {});
  }
}

export async function runAttackSuite(adminUrl: string, appUrl: string, attacks: Attack[] = ATTACKS): Promise<AttackResult[]> {
  const admin = new pg.Pool({ connectionString: adminUrl, max: 2 });
  const app = new pg.Pool({ connectionString: appUrl, max: 2 });
  app.on("error", () => {});
  const guard = createGuardedExecutor(app, SUITE_POLICY);
  const results: AttackResult[] = [];
  try {
    for (const attack of attacks) {
      // Layer set 1: full pg-guard-sql
      let before = await snapshot(admin);
      const g = await guard.run(attack.sql);
      let changed = (await snapshot(admin)) !== before;
      let guarded: AttackResult["guarded"];
      if (changed) guarded = { verdict: "WRITE", detail: "database state changed", ms: g.durationMs };
      else if (g.ok && leaks(g.rows)) guarded = { verdict: "LEAK", detail: `${g.rowCount} rows incl. foreign data`, ms: g.durationMs };
      else if (g.durationMs > SLOW_MS) guarded = { verdict: "SLOW", detail: `${g.durationMs} ms`, ms: g.durationMs };
      else if (g.ok && g.rowCount > SUITE_POLICY.maxRows!) guarded = { verdict: "OVER_CAP", detail: `${g.rowCount} rows`, ms: g.durationMs };
      else if (g.ok) guarded = { verdict: "contained", detail: `ran: ${g.rowCount} rows${g.truncated ? " (capped)" : ""}, own data only`, ms: g.durationMs };
      else if (g.status === "blocked") guarded = { verdict: "blocked", code: g.code, detail: g.code ?? "", ms: g.durationMs };
      else guarded = { verdict: "stopped", detail: `DB error: ${firstLine(g.reason)}`, ms: g.durationMs };

      // Layer set 2: database layers only (validator removed)
      before = await snapshot(admin);
      const d = await runDbOnly(appUrl, attack.sql);
      changed = (await snapshot(admin)) !== before;
      let dbOnly: LayerResult;
      if (changed) dbOnly = { verdict: "WRITE", detail: "database state changed", ms: d.ms };
      else if (leaks(d.rows)) dbOnly = { verdict: "LEAK", detail: `${d.rows.length} rows incl. foreign data`, ms: d.ms };
      else if (d.ms > SLOW_MS) dbOnly = { verdict: "SLOW", detail: `${d.ms} ms${d.error ? `, then ${firstLine(d.error)}` : ""}`, ms: d.ms };
      else if (d.error) dbOnly = { verdict: "stopped", detail: firstLine(d.error), ms: d.ms };
      else dbOnly = { verdict: "contained", detail: `ran: ${d.rows.length} rows, own data only`, ms: d.ms };

      results.push({ attack, guarded, dbOnly });
    }
  } finally {
    await admin.end();
    await app.end();
  }
  return results;
}
