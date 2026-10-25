// Ported from Tuja (tests/pg-guard.integration.test.ts) to the demo shop schema.
import pg from "pg";
import { afterAll, beforeAll, describe, expect, inject, it } from "vitest";
import { createGuardedExecutor, type AuditEvent, type GuardPolicy } from "../src/index.js";

const policy: GuardPolicy = {
  allowedRelations: ["v_orders", "products"],
  role: "ai_reader",
  requiredSettings: ["app.user_id"],
};

describe.skipIf(process.env.SKIP_DB_TESTS === "1")("createGuardedExecutor on Postgres", () => {
  let app: pg.Pool;
  let admin: pg.Pool;
  beforeAll(() => {
    app = new pg.Pool({ connectionString: inject("appUrl"), max: 3 });
    admin = new pg.Pool({ connectionString: inject("adminUrl"), max: 2 });
  });
  afterAll(async () => {
    await app.end();
    await admin.end();
  });
  const alice = { settings: { "app.user_id": "alice" } };
  const bob = { settings: { "app.user_id": "bob" } };

  /** Raw SQL as the read-only role, bypassing the AST validator (to prove RLS and grants alone hold). */
  async function rawAsRole(userId: string, sql: string) {
    const c = await app.connect();
    try {
      await c.query("BEGIN READ ONLY");
      await c.query("SET LOCAL ROLE ai_reader");
      await c.query("SELECT set_config('app.user_id', $1, true)", [userId]);
      return await c.query(sql);
    } finally {
      await c.query("ROLLBACK").catch(() => {});
      c.release();
    }
  }

  it("returns only the caller's rows", async () => {
    const g = createGuardedExecutor(app, policy);
    const res = await g.run("SELECT count(*)::int AS n FROM v_orders", alice);
    const own = await admin.query("SELECT count(*)::int AS n FROM orders WHERE user_id = 'alice'");
    expect(res.ok && res.rows[0].n).toBe(own.rows[0].n);
  });

  it("never leaks the other user's rows even with an always-true filter", async () => {
    const res = await createGuardedExecutor(app, policy).run("SELECT note FROM v_orders WHERE true OR 1=1", alice);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.rows.some((r) => String(r.note).includes("SECRET"))).toBe(false);
  });

  it("the other user sees only their own data", async () => {
    const res = await createGuardedExecutor(app, policy).run("SELECT DISTINCT note FROM v_orders", bob);
    expect(res.ok && res.rows.length > 0 && res.rows.every((r) => String(r.note).startsWith("BOB-SECRET"))).toBe(true);
  });

  it("RLS holds even if the validator is bypassed (base table)", async () => {
    const r = await rawAsRole("alice", "SELECT DISTINCT user_id FROM orders");
    expect(r.rows.map((x) => x.user_id)).toEqual(["alice"]);
  });

  it("grants hide secret tables even if the validator is bypassed", async () => {
    await expect(rawAsRole("alice", "SELECT * FROM users")).rejects.toThrow(/permission denied/);
    await expect(rawAsRole("alice", "SELECT key FROM api_keys")).rejects.toThrow(/permission denied/);
  });

  it("no user id: refused by requiredSettings, and RLS returns nothing anyway", async () => {
    const res = await createGuardedExecutor(app, policy).run("SELECT * FROM v_orders");
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/required setting "app.user_id"/);
    const r = await rawAsRole("", "SELECT count(*)::int AS n FROM orders");
    expect(r.rows[0].n).toBe(0);
  });

  it("writes fail inside the read-only transaction even if the validator is bypassed", async () => {
    await expect(rawAsRole("alice", "DELETE FROM orders")).rejects.toThrow(/read-only|permission denied/);
  });

  it("enforces statement_timeout", async () => {
    const res = await createGuardedExecutor(app, { ...policy, timeoutMs: 300 }).run(
      "SELECT count(*) FROM products a, products b, products c, products d",
      alice,
    );
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/statement timeout|canceling statement/);
  });

  it("caps rows and reports truncation", async () => {
    const res = await createGuardedExecutor(app, { ...policy, maxRows: 5 }).run("SELECT * FROM products", alice);
    expect(res.ok && res.rowCount === 5 && res.truncated).toBe(true);
    if (res.ok) expect(res.executedSql).toContain("LIMIT 6");
  });

  it("a trailing line comment cannot swallow the LIMIT wrapper", async () => {
    const res = await createGuardedExecutor(app, { ...policy, maxRows: 3 }).run("SELECT * FROM products -- no limit please", alice);
    expect(res.ok && res.rowCount === 3 && res.truncated).toBe(true);
  });

  it("audits blocked, failed and successful attempts", async () => {
    const events: AuditEvent[] = [];
    const g = createGuardedExecutor(app, { ...policy, timeoutMs: 200 }, {
      onAudit: (e) => {
        events.push(e);
        throw new Error("audit sink down"); // must not break the request
      },
    });
    await g.run("DROP TABLE orders", alice);
    await g.run("SELECT count(*) FROM products a, products b, products c, products d", alice);
    const ok = await g.run("SELECT 1 AS one", alice);
    expect(ok.ok).toBe(true);
    expect(events.map((e) => e.status)).toEqual(["blocked", "error", "ok"]);
    expect(events[0]).toMatchObject({ code: "NOT_SELECT", settings: { "app.user_id": "alice" } });
  });

  it("per-call settings override policy settings", async () => {
    const g = createGuardedExecutor(app, { ...policy, settings: { "app.user_id": "alice" } });
    const res = await g.run("SELECT count(*)::int AS n FROM v_orders", bob);
    expect(res.ok && res.rows[0].n).toBe(25);
  });

  it("describe() lists the columns of an allowlisted view and refuses others", async () => {
    const g = createGuardedExecutor(app, policy);
    const cols = await g.describe("v_orders", alice);
    expect(cols.map((c) => c.name)).toEqual(["id", "created_at", "product", "quantity", "total", "note"]);
    await expect(g.describe("users", alice)).rejects.toThrow(/not in the allowlist/);
  });

  it("the connection is clean after a query (role and settings were transaction-local)", async () => {
    const g = createGuardedExecutor(app, policy);
    await g.run("SELECT 1", alice);
    const c = await app.connect();
    try {
      const r = await c.query("SELECT current_user AS u, current_setting('app.user_id', true) AS s");
      expect(r.rows[0].u).toBe("pgguard_app");
      expect(r.rows[0].s ?? "").toBe("");
    } finally {
      c.release();
    }
  });
});
