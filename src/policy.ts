import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { assertSafePolicy } from "./executor.js";
import type { GuardPolicy } from "./types.js";

const settingName = z.string().regex(/^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/, "use prefix.name, e.g. app.user_id");

export const policySchema = z
  .object({
    allowedRelations: z.array(z.string().min(1)).min(1),
    descriptions: z.record(z.string(), z.string()).optional(),
    schema: z.string().optional(),
    allowedFunctions: z.array(z.string()).optional(),
    extraFunctions: z.array(z.string()).optional(),
    maxSqlLength: z.number().int().positive().optional(),
    allowRecursiveCte: z.boolean().optional(),
    maxRows: z.number().int().positive().optional(),
    timeoutMs: z.number().int().positive().optional(),
    role: z.string().optional(),
    settings: z.record(settingName, z.string()).optional(),
    requiredSettings: z.array(settingName).optional(),
  })
  .strict();

/** Parse and check a policy object (throws with a readable message). */
export function parsePolicy(input: unknown): GuardPolicy {
  const r = policySchema.safeParse(input);
  if (!r.success) {
    throw new Error(`Invalid pg-guard-sql policy: ${r.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")}`);
  }
  const policy = r.data as GuardPolicy;
  assertSafePolicy(policy);
  return policy;
}

/** Load a policy from a .json, .yaml or .yml file. */
export function loadPolicyFile(path: string): GuardPolicy {
  const text = readFileSync(path, "utf8");
  const ext = extname(path).toLowerCase();
  const data = ext === ".json" ? JSON.parse(text) : parseYaml(text);
  return parsePolicy(data);
}
