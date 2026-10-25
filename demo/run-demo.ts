/**
 * Demo: Alice tries to read Bob's data with injected SQL. Run `npm run demo:up` first.
 * Connects as the low-privilege login `pgguard_app`; every query goes through pg-guard-sql.
 */
import pg from "pg";
import { fileURLToPath } from "node:url";
import { createGuardedExecutor, loadPolicyFile } from "../src/index.js";

const url = process.env.DEMO_DATABASE_URL ?? "postgresql://pgguard_app:pgguard_app@localhost:54329/shop";
const policy = loadPolicyFile(fileURLToPath(new URL("./policy.yaml", import.meta.url)));

const attempts: [string, string][] = [
  ["Alice's own orders", "SELECT count(*) AS orders, sum(total) AS spent FROM v_orders"],
  ["Always-true filter", "SELECT count(*) AS rows_seen FROM v_orders WHERE true OR 1=1"],
  ["Look for Bob's notes", "SELECT note FROM v_orders WHERE note LIKE '%BOB%'"],
  ["Base table, Bob's id", "SELECT * FROM orders WHERE user_id = 'bob'"],
  ["Switch the RLS user", "SELECT set_config('app.user_id', 'bob', true), * FROM v_orders"],
  ["Stacked: switch user, then read", "SELECT 1; SELECT set_config('app.user_id','bob',false); SELECT * FROM v_orders"],
  ["Password hashes", "SELECT email, password_hash FROM users"],
  ["UNION with API keys", "SELECT note FROM v_orders UNION ALL SELECT key FROM api_keys"],
  ["SECURITY DEFINER helper", "SELECT * FROM admin_dump_users()"],
  ["Writing CTE", "WITH d AS (DELETE FROM orders RETURNING *) SELECT count(*) FROM d"],
  ["Comment trick", "SELECT count(*) FROM v_orders /* nested /* */ ; DROP TABLE orders; */"],
  ["Sleep", "SELECT pg_sleep(30)"],
  ["8M-row cross join", "SELECT a.name, b.name, c.name FROM products a, products b, products c"],
];

async function main() {
  const pool = new pg.Pool({ connectionString: url, max: 2 });
  const guard = createGuardedExecutor(pool, policy);
  const as = (user: string) => ({ settings: { "app.user_id": user } });

  console.log(`pg-guard-sql demo: connected as pgguard_app, role ${policy.role}, allowlist ${policy.allowedRelations.join(", ")}\n`);
  let leaks = 0;
  for (const [label, sql] of attempts) {
    const r = await guard.run(sql, as("alice"));
    const text = r.ok ? JSON.stringify(r.rows) : "";
    const leaked = /SECRET|bob@/.test(text);
    if (leaked) leaks++;
    const outcome = r.ok
      ? `ran: ${r.rowCount} row(s)${r.truncated ? " (capped)" : ""} ${r.rowCount && r.rowCount <= 2 ? JSON.stringify(r.rows) : ""}`
      : `${r.status}: ${r.code ?? r.reason.split("\n")[0]}`;
    console.log(`${leaked ? "LEAK" : " ok "}  ${label.padEnd(32)} ${outcome}`);
  }
  const b = await guard.run("SELECT count(*) AS orders FROM v_orders", as("bob"));
  console.log(`\nSame view as Bob: ${b.ok ? JSON.stringify(b.rows[0]) : b.reason}`);
  console.log(`\nAlice saw ${leaks} of Bob's rows or secrets.`);
  await pool.end();
  if (leaks) process.exit(1);
}

main().catch((e) => {
  console.error(e.message);
  console.error("Is the demo database up? npm run demo:up");
  process.exit(1);
});
