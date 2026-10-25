// Ported from Tuja (src/lib/pg-guard/__tests__/validate.test.ts) plus pg-guard-sql additions.
import { describe, expect, it } from "vitest";
import { validate, DEFAULT_ALLOWED_FUNCTIONS } from "../src/index.js";
import type { GuardPolicy } from "../src/index.js";

const policy: GuardPolicy = { allowedRelations: ["v_transactions", "v_accounts", "v_fx_rates"] };

const allowed: string[] = [
  "SELECT * FROM v_transactions",
  "select sum(amount) from v_transactions where category = 'Food' and booked_at >= date '2026-09-01';",
  "SELECT category, round(sum(-amount), 2) AS spent FROM v_transactions WHERE direction = 'out' GROUP BY 1 ORDER BY 2 DESC LIMIT 5",
  "WITH m AS (SELECT date_trunc('month', booked_at) AS mo, sum(amount) s FROM v_transactions GROUP BY 1) SELECT * FROM m ORDER BY mo",
  "SELECT a.name, count(*) FROM v_transactions t JOIN v_accounts a ON a.id = t.account_id GROUP BY a.name",
  "SELECT extract(month from booked_at) m, count(*) FROM v_transactions GROUP BY 1",
  "SELECT * FROM v_transactions WHERE merchant ILIKE '%coupang%' AND booked_at > current_date - interval '30 days'",
  "SELECT code, rate_uzs FROM public.v_fx_rates ORDER BY date DESC LIMIT 3",
  "SELECT merchant FROM v_transactions UNION SELECT name FROM v_accounts",
  "SELECT * FROM v_transactions WHERE amount < (SELECT avg(amount) FROM v_transactions)",
  "SELECT merchant, sum(amount) OVER (PARTITION BY category) FROM v_transactions",
  "SELECT 1 -- trailing comment",
  "SELECT coalesce(nullif(trim(merchant), ''), 'n/a') FROM v_transactions",
  "SELECT substring(merchant from 1 for 3), position('a' in merchant) FROM v_transactions",
];

/** [sql, expected first error code] */
const blocked: [string, string][] = [
  ["DROP TABLE transactions", "NOT_SELECT"],
  ["DELETE FROM transactions", "NOT_SELECT"],
  ["UPDATE bank_accounts SET balance_minor = 0", "NOT_SELECT"],
  ["INSERT INTO transactions DEFAULT VALUES", "NOT_SELECT"],
  ["SELECT 1; DROP TABLE users", "MULTIPLE_STATEMENTS"],
  ["SELECT * FROM v_transactions; SELECT * FROM users", "MULTIPLE_STATEMENTS"],
  ["SELECT * FROM users", "FORBIDDEN_RELATION"],
  ["SELECT * FROM transactions", "FORBIDDEN_RELATION"],
  ["SELECT access_token_enc FROM plaid_items", "FORBIDDEN_RELATION"],
  ["SELECT * FROM sessions", "FORBIDDEN_RELATION"],
  ["SELECT * FROM pg_catalog.pg_shadow", "FORBIDDEN_SCHEMA"],
  ["SELECT * FROM information_schema.tables", "FORBIDDEN_SCHEMA"],
  ["SELECT * FROM pg_user", "FORBIDDEN_RELATION"],
  ["SELECT pg_sleep(10)", "FORBIDDEN_FUNCTION"],
  ["SELECT * FROM v_transactions WHERE pg_sleep(5) IS NULL", "FORBIDDEN_FUNCTION"],
  ["SELECT set_config('app.user_id', 'someone-else', true)", "FORBIDDEN_FUNCTION"],
  ["SELECT current_setting('app.user_id')", "FORBIDDEN_FUNCTION"],
  ["SELECT pg_read_file('/etc/passwd')", "FORBIDDEN_FUNCTION"],
  ["SELECT lo_import('/etc/passwd')", "FORBIDDEN_FUNCTION"],
  ["SELECT dblink_exec('host=evil', 'drop table x')", "FORBIDDEN_FUNCTION"],
  ["SELECT * FROM generate_series(1, 100000000)", "FORBIDDEN_NODE"],
  ["SELECT * INTO stolen FROM v_transactions", "SELECT_INTO"],
  ["SELECT * FROM v_transactions FOR UPDATE", "LOCKING_CLAUSE"],
  ["WITH d AS (DELETE FROM transactions RETURNING *) SELECT * FROM d", "DATA_MODIFYING_CTE"],
  ["WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT * FROM r", "RECURSIVE_CTE"],
  ["SELECT 'pg_authid'::regclass", "FORBIDDEN_CAST"],
  ["COPY transactions TO '/tmp/x'", "NOT_SELECT"],
  ["SET ROLE postgres", "NOT_SELECT"],
  ["RESET ROLE", "NOT_SELECT"],
  ["BEGIN; SELECT 1; COMMIT", "MULTIPLE_STATEMENTS"],
  ["EXPLAIN ANALYZE SELECT * FROM v_transactions", "NOT_SELECT"],
  ["SELECT * FROM (WITH sessions AS (SELECT 1) SELECT * FROM sessions) a, sessions", "FORBIDDEN_RELATION"],
  ["WITH a AS (SELECT * FROM sessions), sessions AS (SELECT 1) SELECT * FROM a", "FORBIDDEN_RELATION"],
  ["SELECT * FROM v_transactions WHERE id = $1", "FORBIDDEN_NODE"],
  ["SELECT query_to_xml('select * from users', true, true, '')", "FORBIDDEN_FUNCTION"],
  ["SELECT public.evil()", "FORBIDDEN_FUNCTION"],
  ["SELEC * FROM v_transactions", "PARSE_ERROR"],
  ["", "EMPTY"],
  ["SELECT 1 " + "x".repeat(5000), "TOO_LONG"],
  ["SELECT 1\u0000; DROP TABLE users", "FORBIDDEN_CHAR"],
  ["SELECT '<a/>'::xml", "FORBIDDEN_CAST"],
  ['SELECT * FROM "V_TRANSACTIONS"', "FORBIDDEN_RELATION"],
  ['SELECT * FROM "PUBLIC".v_transactions', "FORBIDDEN_SCHEMA"],
  ["SELECT * FROM shop.public.v_transactions", "FORBIDDEN_SCHEMA"],
  ["SELECT evil.count(*) FROM v_transactions", "FORBIDDEN_FUNCTION"],
];

describe("validate (ported from Tuja)", () => {
  it.each(allowed)("allows: %s", async (sql) => {
    const r = await validate(sql, policy);
    expect(r.allowed, JSON.stringify(r)).toBe(true);
  });

  it.each(blocked)("blocks: %s", async (sql, code) => {
    const r = await validate(sql, policy);
    expect(r.allowed).toBe(false);
    if (!r.allowed) expect(r.code).toBe(code);
  });

  it("strips trailing semicolons and reports relations/functions", async () => {
    const r = await validate("SELECT count(*) FROM v_accounts;;", policy);
    expect(r).toMatchObject({ allowed: true, sql: "SELECT count(*) FROM v_accounts", relations: ["v_accounts"], functions: ["count"], reasons: [] });
  });
});

describe("validate (pg-guard-sql additions)", () => {
  it("reports every violation, not only the first", async () => {
    const r = await validate("SELECT pg_sleep(1), email FROM users JOIN pg_catalog.pg_authid ON true", policy);
    expect(r.allowed).toBe(false);
    if (r.allowed) return;
    expect(r.violations.map((v) => v.code).sort()).toEqual(["FORBIDDEN_FUNCTION", "FORBIDDEN_RELATION", "FORBIDDEN_SCHEMA"]);
    expect(r.reasons).toHaveLength(3);
    expect(r.reasons[0]).toMatch(/^FORBIDDEN_/);
  });

  it("supports a non-public schema", async () => {
    const p: GuardPolicy = { schema: "analytics", allowedRelations: ["events", "analytics.sessions"] };
    expect((await validate("SELECT * FROM events JOIN analytics.sessions USING (id)", p)).allowed).toBe(true);
    const r = await validate("SELECT * FROM public.events", p);
    expect(!r.allowed && r.code).toBe("FORBIDDEN_SCHEMA");
  });

  it("extraFunctions extends and allowedFunctions replaces the defaults", async () => {
    expect((await validate("SELECT md5(merchant) FROM v_transactions", { ...policy, extraFunctions: ["md5"] })).allowed).toBe(true);
    const r = await validate("SELECT count(*) FROM v_transactions", { ...policy, allowedFunctions: ["sum"] });
    expect(!r.allowed && r.code).toBe("FORBIDDEN_FUNCTION");
    expect(DEFAULT_ALLOWED_FUNCTIONS).not.toContain("pg_sleep");
  });

  it("allows a self-referencing recursive CTE only when enabled", async () => {
    const sql = "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 10) SELECT * FROM r";
    expect((await validate(sql, policy)).allowed).toBe(false);
    expect((await validate(sql, { ...policy, allowRecursiveCte: true })).allowed).toBe(true);
  });

  it("a CTE name does not shadow a forbidden table outside its scope", async () => {
    const r = await validate("WITH x AS (SELECT 1) SELECT * FROM x, users", policy);
    expect(!r.allowed && r.code).toBe("FORBIDDEN_RELATION");
  });

  it("treats non-string input as empty", async () => {
    const r = await validate(undefined as unknown as string, policy);
    expect(!r.allowed && r.code).toBe("EMPTY");
  });
});
