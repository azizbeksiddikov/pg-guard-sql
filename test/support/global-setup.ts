import type { TestProject } from "vitest/node";
import { startTestDb, type TestDb } from "./db.js";

let db: TestDb | undefined;

/** One Postgres container for the whole run. Set SKIP_DB_TESTS=1 to run only the pure tests. */
export async function setup(project: TestProject) {
  if (process.env.SKIP_DB_TESTS === "1") return;
  db = await startTestDb();
  project.provide("adminUrl", db.adminUrl);
  project.provide("appUrl", db.appUrl);
}

export async function teardown() {
  await db?.stop();
}

declare module "vitest" {
  export interface ProvidedContext {
    adminUrl: string;
    appUrl: string;
  }
}
