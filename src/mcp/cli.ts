#!/usr/bin/env node
import pg from "pg";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createGuardedExecutor } from "../executor.js";
import { loadPolicyFile } from "../policy.js";
import type { GuardPolicy } from "../types.js";
import { createServer } from "./server.js";

function fail(msg: string): never {
  process.stderr.write(`pg-guard-sql: ${msg}\n`);
  process.exit(1);
}

function argValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

async function main() {
  const url = process.env.DATABASE_URL;
  const policyPath = argValue("--policy") ?? process.env.PG_GUARD_POLICY;
  if (!url) fail("DATABASE_URL is not set");
  if (!policyPath) fail("set PG_GUARD_POLICY (or pass --policy <file.json|yaml>)");

  let policy: GuardPolicy;
  try {
    policy = loadPolicyFile(policyPath);
  } catch (e) {
    fail((e as Error).message);
  }
  // Optional per-deployment settings (e.g. the RLS user) from the environment, merged over the file.
  if (process.env.PG_GUARD_SETTINGS) {
    try {
      policy = { ...policy, settings: { ...(policy.settings ?? {}), ...JSON.parse(process.env.PG_GUARD_SETTINGS) } };
    } catch {
      fail('PG_GUARD_SETTINGS must be JSON, e.g. {"app.user_id":"alice"}');
    }
  }
  if (!policy.role) process.stderr.write("pg-guard-sql: warning: no policy.role set; queries run as the connecting user\n");

  const pool = new pg.Pool({ connectionString: url, max: 4, application_name: "pg-guard-sql" });
  pool.on("error", (e) => process.stderr.write(`pg-guard-sql: pool error: ${e.message}\n`));
  const executor = createGuardedExecutor(pool, policy, {
    onAudit: (e) => {
      // stdout is the MCP channel; audit goes to stderr as one JSON line per attempt.
      process.stderr.write(`${JSON.stringify({ audit: { ...e, sql: e.sql.slice(0, 2000) } })}\n`);
    },
  });
  const server = createServer(executor);
  await server.connect(new StdioServerTransport());
  const shutdown = async () => {
    await server.close().catch(() => {});
    await pool.end().catch(() => {});
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((e) => fail((e as Error).stack ?? String(e)));
