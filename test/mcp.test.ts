import pg from "pg";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterAll, beforeAll, describe, expect, inject, it } from "vitest";
import { createGuardedExecutor, loadPolicyFile } from "../src/index.js";
import { createServer } from "../src/mcp/server.js";
import { fileURLToPath } from "node:url";

type TextResult = { content: { type: string; text: string }[]; isError?: boolean };
const body = (r: unknown) => JSON.parse((r as TextResult).content[0].text);

describe.skipIf(process.env.SKIP_DB_TESTS === "1")("MCP server", () => {
  let pool: pg.Pool;
  let client: Client;

  beforeAll(async () => {
    pool = new pg.Pool({ connectionString: inject("appUrl"), max: 2 });
    const policy = loadPolicyFile(fileURLToPath(new URL("../demo/policy.yaml", import.meta.url)));
    const server = createServer(createGuardedExecutor(pool, { ...policy, settings: { "app.user_id": "alice" } }));
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    client = new Client({ name: "test", version: "0.0.0" });
    await client.connect(ct);
  });
  afterAll(async () => {
    await client.close();
    await pool.end();
  });

  it("exposes the four read-only tools", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["describe_table", "list_allowed_tables", "run_readonly_sql", "validate_sql"]);
    expect(tools.every((t) => t.annotations?.readOnlyHint === true)).toBe(true);
  });

  it("list_allowed_tables", async () => {
    const r = body(await client.callTool({ name: "list_allowed_tables", arguments: {} }));
    expect(r.tables.map((t: { name: string }) => t.name)).toEqual(["v_orders", "products"]);
    expect(r.max_rows).toBe(500);
    expect(r.allowed_functions).toContain("count");
  });

  it("describe_table", async () => {
    const r = body(await client.callTool({ name: "describe_table", arguments: { table: "products" } }));
    expect(r.columns.map((c: { name: string }) => c.name)).toEqual(["id", "name", "price"]);
    const denied = (await client.callTool({ name: "describe_table", arguments: { table: "users" } })) as TextResult;
    expect(denied.isError).toBe(true);
  });

  it("validate_sql returns reasons", async () => {
    const ok = body(await client.callTool({ name: "validate_sql", arguments: { sql: "SELECT count(*) FROM v_orders" } }));
    expect(ok).toEqual({ allowed: true, relations: ["v_orders"], functions: ["count"] });
    const bad = body(await client.callTool({ name: "validate_sql", arguments: { sql: "SELECT * FROM users; DROP TABLE orders" } }));
    expect(bad).toMatchObject({ allowed: false, code: "MULTIPLE_STATEMENTS" });
  });

  it("run_readonly_sql returns only Alice's rows, and blocks injection", async () => {
    const r = body(await client.callTool({ name: "run_readonly_sql", arguments: { sql: "SELECT note, total FROM v_orders WHERE true OR 1=1" } }));
    expect(r.ok).toBe(true);
    expect(r.row_count).toBe(20);
    expect(JSON.stringify(r.rows)).not.toContain("SECRET");
    const blocked = (await client.callTool({ name: "run_readonly_sql", arguments: { sql: "SELECT set_config('app.user_id','bob',true), * FROM v_orders" } })) as TextResult;
    expect(blocked.isError).toBe(true);
    expect(body(blocked)).toMatchObject({ ok: false, status: "blocked", code: "FORBIDDEN_FUNCTION" });
  });
});
