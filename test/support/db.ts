import { fileURLToPath } from "node:url";
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from "@testcontainers/postgresql";

export const INIT_SQL = fileURLToPath(new URL("../../demo/init.sql", import.meta.url));

export interface TestDb {
  /** Owner (superuser) connection: used only to verify state, never for attacks. */
  adminUrl: string;
  /** Low-privilege login used by pg-guard-sql (member of ai_reader, NOINHERIT). */
  appUrl: string;
  stop(): Promise<void>;
}

/** Start Postgres 17 in Docker with the demo schema, or reuse one given by env (CI / local compose). */
export async function startTestDb(): Promise<TestDb> {
  if (process.env.PG_GUARD_TEST_ADMIN_URL && process.env.PG_GUARD_TEST_APP_URL) {
    return { adminUrl: process.env.PG_GUARD_TEST_ADMIN_URL, appUrl: process.env.PG_GUARD_TEST_APP_URL, stop: async () => {} };
  }
  const c: StartedPostgreSqlContainer = await new PostgreSqlContainer("postgres:17-alpine")
    .withDatabase("shop")
    .withUsername("owner")
    .withPassword("owner")
    .withCopyFilesToContainer([{ source: INIT_SQL, target: "/docker-entrypoint-initdb.d/init.sql" }])
    .start();
  const host = c.getHost();
  const port = c.getPort();
  return {
    adminUrl: `postgresql://owner:owner@${host}:${port}/shop`,
    appUrl: `postgresql://pgguard_app:pgguard_app@${host}:${port}/shop`,
    stop: async () => {
      await c.stop();
    },
  };
}
