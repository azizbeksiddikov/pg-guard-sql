import { describe, expect, inject, it } from "vitest";
import { validate } from "../src/index.js";
import { ATTACKS } from "./support/attacks.js";
import { runAttackSuite, SAFE, SUITE_POLICY, type AttackResult } from "./support/run-attacks.js";

describe("attack suite: validator expectations (no database)", () => {
  it("has at least 25 attacks", () => {
    expect(ATTACKS.length).toBeGreaterThanOrEqual(25);
  });

  it.each(ATTACKS.map((a) => [a.id, a.name, a] as const))("#%i %s", async (_id, _name, attack) => {
    const r = await validate(attack.sql, SUITE_POLICY);
    if (attack.expect === "allow") {
      expect(r.allowed, JSON.stringify(r)).toBe(true);
    } else {
      expect(r.allowed).toBe(false);
      if (!r.allowed) expect(r.violations.map((v) => v.code)).toContain(attack.expect);
    }
  });
});

describe.skipIf(process.env.SKIP_DB_TESTS === "1")("attack suite on real Postgres", () => {
  let results: AttackResult[] = [];

  it("runs every attack through pg-guard-sql and through the DB layers alone", async () => {
    results = await runAttackSuite(inject("adminUrl"), inject("appUrl"));
    expect(results).toHaveLength(ATTACKS.length);
  }, 300_000);

  it("pg-guard-sql: no leak, no write, no slow query, no row-cap breach", () => {
    const bad = results.filter((r) => !SAFE.includes(r.guarded.verdict));
    expect(bad.map((r) => `#${r.attack.id} ${r.attack.name}: ${r.guarded.verdict} ${r.guarded.detail}`)).toEqual([]);
  });

  it("validator blocks exactly the attacks expected to be blocked", () => {
    for (const r of results) {
      if (r.attack.expect === "allow") expect(r.guarded.verdict, r.attack.name).not.toBe("blocked");
      else expect(r.guarded.verdict, r.attack.name).toBe("blocked");
    }
  });

  it("documents why the validator is needed: the DB layers alone miss RLS switching and SECURITY DEFINER leaks", () => {
    const missed = results.filter((r) => !SAFE.includes(r.dbOnly.verdict)).map((r) => r.attack.name);
    expect(missed).toEqual(
      expect.arrayContaining(["Switch RLS user, then read", "SECURITY DEFINER function in FROM"]),
    );
  });
});
