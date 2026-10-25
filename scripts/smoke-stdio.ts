/** Spawn the built MCP server over stdio (as Claude Desktop would) and call each tool once. */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/mcp/cli.js"],
  env: {
    PATH: process.env.PATH ?? "",
    DATABASE_URL: process.env.SMOKE_DATABASE_URL ?? "postgresql://pgguard_app:pgguard_app@localhost:54329/shop",
    PG_GUARD_POLICY: "demo/policy.yaml",
    PG_GUARD_SETTINGS: JSON.stringify({ "app.user_id": "alice" }),
  },
  stderr: "pipe",
});
const client = new Client({ name: "smoke", version: "0.0.0" });
await client.connect(transport);
const text = (r: unknown) => (r as { content: { text: string }[] }).content[0].text;
console.log("tools:", (await client.listTools()).tools.map((t) => t.name).join(", "));
console.log("list_allowed_tables:", text(await client.callTool({ name: "list_allowed_tables", arguments: {} })).slice(0, 200), "...");
console.log("describe_table v_orders:", JSON.parse(text(await client.callTool({ name: "describe_table", arguments: { table: "v_orders" } }))).columns.map((c: { name: string; type: string }) => `${c.name}:${c.type}`).join(", "));
console.log("validate_sql:", text(await client.callTool({ name: "validate_sql", arguments: { sql: "SELECT * FROM users; DROP TABLE orders" } })));
const run = JSON.parse(text(await client.callTool({ name: "run_readonly_sql", arguments: { sql: "SELECT count(*) AS n, bool_or(note LIKE '%SECRET%') AS saw_bob FROM v_orders WHERE true OR 1=1" } })));
console.log("run_readonly_sql:", JSON.stringify(run.rows));
await client.close();
