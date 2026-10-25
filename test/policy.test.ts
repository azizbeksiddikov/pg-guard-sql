import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createGuardedExecutor, loadPolicyFile, parsePolicy } from "../src/index.js";
import type { PoolLike } from "../src/index.js";

describe("policy", () => {
  it("loads the demo YAML policy", () => {
    const p = loadPolicyFile(fileURLToPath(new URL("../demo/policy.yaml", import.meta.url)));
    expect(p.allowedRelations).toEqual(["v_orders", "products"]);
    expect(p.role).toBe("ai_reader");
    expect(p.requiredSettings).toEqual(["app.user_id"]);
  });

  it("loads JSON", () => {
    const dir = mkdtempSync(join(tmpdir(), "pgguard-"));
    const f = join(dir, "p.json");
    writeFileSync(f, JSON.stringify({ allowedRelations: ["t"], maxRows: 10 }));
    expect(loadPolicyFile(f)).toEqual({ allowedRelations: ["t"], maxRows: 10 });
  });

  it.each([
    [{}, /allowedRelations/],
    [{ allowedRelations: [] }, /allowedRelations/],
    [{ allowedRelations: ["t"], role: "x; DROP TABLE t" }, /invalid role/],
    [{ allowedRelations: ["t"], schema: "public; --" }, /invalid schema/],
    [{ allowedRelations: ["t"], settings: { user_id: "a" } }, /settings/],
    [{ allowedRelations: ["t"], unknownKey: 1 }, /Unrecognized|unrecognized/],
  ])("rejects %j", (input, msg) => {
    expect(() => parsePolicy(input)).toThrow(msg);
  });

  it("createGuardedExecutor rejects unsafe policies before touching the database", () => {
    const pool: PoolLike = { connect: () => Promise.reject(new Error("must not connect")) };
    expect(() => createGuardedExecutor(pool, { allowedRelations: ["t"], role: "a b" })).toThrow(/invalid role/);
  });
});
