import { parse } from "libpg-query";
import type { GuardErrorCode, GuardPolicy, ValidationResult, Violation } from "./types.js";

/** Conservative default: aggregates, math, string, date and window helpers. No I/O, sleeps or settings. */
export const DEFAULT_ALLOWED_FUNCTIONS: readonly string[] = [
  "count", "sum", "avg", "min", "max", "bool_and", "bool_or", "string_agg", "array_agg",
  "round", "abs", "ceil", "ceiling", "floor", "trunc", "sign", "greatest", "least", "coalesce", "nullif",
  "lower", "upper", "trim", "btrim", "ltrim", "rtrim", "length", "char_length", "substring", "substr",
  "position", "strpos", "replace", "concat", "concat_ws", "left", "right", "split_part", "initcap",
  "date_trunc", "date_part", "extract", "to_char", "to_date", "make_date", "age", "now",
  "percentile_cont", "percentile_disc", "stddev", "variance", "row_number", "rank", "dense_rank",
  "lag", "lead", "first_value", "last_value", "ntile",
];

/** Casts that resolve catalog objects by name (reg*) or invoke a complex parser (xml). */
function isForbiddenCast(type: string): boolean {
  return (type.startsWith("reg") && type !== "real") || type === "xml";
}

/** Node types that are never acceptable anywhere in the tree. */
const FORBIDDEN_NODES: Record<string, GuardErrorCode> = {
  RangeFunction: "FORBIDDEN_NODE", // SELECT * FROM some_function()
  RangeTableFunc: "FORBIDDEN_NODE", // XMLTABLE
  RangeTableFuncCol: "FORBIDDEN_NODE",
  JsonTable: "FORBIDDEN_NODE",
  ParamRef: "FORBIDDEN_NODE",
  CurrentOfExpr: "FORBIDDEN_NODE",
  XmlExpr: "FORBIDDEN_NODE",
  XmlSerialize: "FORBIDDEN_NODE",
  LockingClause: "LOCKING_CLAUSE",
  IntoClause: "SELECT_INTO",
  InsertStmt: "DATA_MODIFYING_CTE",
  UpdateStmt: "DATA_MODIFYING_CTE",
  DeleteStmt: "DATA_MODIFYING_CTE",
  MergeStmt: "DATA_MODIFYING_CTE",
  CreateTableAsStmt: "DATA_MODIFYING_CTE",
  CopyStmt: "DATA_MODIFYING_CTE",
  CallStmt: "DATA_MODIFYING_CTE",
  DoStmt: "DATA_MODIFYING_CTE",
  VariableSetStmt: "DATA_MODIFYING_CTE",
  NotifyStmt: "DATA_MODIFYING_CTE",
  ListenStmt: "DATA_MODIFYING_CTE",
  TransactionStmt: "DATA_MODIFYING_CTE",
};

const NODE_REASON: Partial<Record<GuardErrorCode, string>> = {
  LOCKING_CLAUSE: "FOR UPDATE/SHARE is not allowed",
  SELECT_INTO: "SELECT INTO is not allowed",
};

function stringList(nodes: unknown): string[] {
  if (!Array.isArray(nodes)) return [];
  return nodes
    .map((n) => (n && typeof n === "object" && "String" in n ? (n as { String: { sval?: string } }).String.sval : undefined))
    .filter((s): s is string => typeof s === "string");
}

export function stripTrailingSemicolons(sql: string): string {
  let s = sql.trim();
  while (s.endsWith(";")) s = s.slice(0, -1).trimEnd();
  return s;
}

/** Split an allowlist entry `schema.name` / `name` and keep only entries in `schema`. */
function relationSet(policy: GuardPolicy, schema: string): Set<string> {
  const out = new Set<string>();
  for (const r of policy.allowedRelations) {
    const dot = r.lastIndexOf(".");
    if (dot === -1) out.add(r);
    else if (r.slice(0, dot) === schema) out.add(r.slice(dot + 1));
  }
  return out;
}

export function allowedFunctionSet(policy: GuardPolicy): Set<string> {
  return new Set([...(policy.allowedFunctions ?? DEFAULT_ALLOWED_FUNCTIONS), ...(policy.extraFunctions ?? [])]);
}

/**
 * Check that `sql` is exactly one plain SELECT that reads only allowlisted relations and calls only
 * allowlisted functions, using Postgres's own parser (libpg_query compiled to WASM).
 * Names are compared exactly as Postgres resolves them (unquoted identifiers are already folded to
 * lower case by the parser; `"Users"` stays `Users` and does not match an allowlisted `users`).
 */
export async function validate(sql: string, policy: GuardPolicy): Promise<ValidationResult> {
  const blocked = (violations: Violation[]): ValidationResult => ({
    allowed: false,
    code: violations[0].code,
    reasons: violations.map((v) => `${v.code}: ${v.reason}`),
    violations,
  });
  const one = (code: GuardErrorCode, reason: string) => blocked([{ code, reason }]);

  const maxLen = policy.maxSqlLength ?? 4000;
  const schema = policy.schema ?? "public";
  const trimmed = stripTrailingSemicolons(typeof sql === "string" ? sql : "");
  if (!trimmed) return one("EMPTY", "Empty query");
  if (trimmed.length > maxLen) return one("TOO_LONG", `Query longer than ${maxLen} characters`);
  // libpg_query and the wire protocol treat NUL as end of string; never let the two disagree.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000]/.test(trimmed)) return one("FORBIDDEN_CHAR", "NUL bytes are not allowed in SQL");

  let tree: { stmts?: { stmt: Record<string, unknown> }[] };
  try {
    tree = (await parse(trimmed)) as typeof tree;
  } catch (e) {
    return one("PARSE_ERROR", `Postgres parser rejected the query: ${(e as Error).message}`);
  }

  const stmts = tree.stmts ?? [];
  if (stmts.length !== 1) return one("MULTIPLE_STATEMENTS", `Expected exactly 1 statement, got ${stmts.length}`);

  const root = stmts[0].stmt;
  const rootType = Object.keys(root)[0];
  if (rootType !== "SelectStmt") return one("NOT_SELECT", `Only SELECT is allowed, got ${rootType}`);

  const allowedRelations = relationSet(policy, schema);
  const allowedFunctions = allowedFunctionSet(policy);

  const cteNames = new Set<string>();
  const relations = new Set<string>();
  const functions = new Set<string>();
  const violations: Violation[] = [];
  const seen = new Set<string>();
  const add = (code: GuardErrorCode, reason: string) => {
    const k = `${code}|${reason}`;
    if (!seen.has(k)) {
      seen.add(k);
      violations.push({ code, reason });
    }
  };

  const visit = (node: unknown): void => {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const child of node) visit(child);
      return;
    }
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      const forbidden = FORBIDDEN_NODES[key];
      if (forbidden) {
        add(forbidden, NODE_REASON[forbidden] ?? `${key} is not allowed`);
        continue; // do not descend: its contents are irrelevant once it is rejected
      }
      if (key === "intoClause" && value) {
        add("SELECT_INTO", NODE_REASON.SELECT_INTO!);
        continue;
      }
      if (key === "lockingClause" && Array.isArray(value) && value.length) {
        add("LOCKING_CLAUSE", NODE_REASON.LOCKING_CLAUSE!);
        continue;
      }
      if (key === "withClause" || key === "WithClause") {
        // Only the root statement may have a WITH clause, so CTE name scoping is unambiguous.
        add("FORBIDDEN_NODE", "WITH is only allowed at the top level of the query");
        continue;
      }
      if (key === "RangeVar") {
        const rv = value as { relname?: string; schemaname?: string; catalogname?: string };
        const rel = rv.relname ?? "";
        if (rv.catalogname || (rv.schemaname && rv.schemaname !== schema)) {
          add("FORBIDDEN_SCHEMA", `Schema "${rv.schemaname ?? rv.catalogname}" is not allowed (only "${schema}")`);
        } else if (!rv.schemaname && cteNames.has(rel)) {
          // reference to a CTE defined earlier in this statement
        } else if (!allowedRelations.has(rel)) {
          add("FORBIDDEN_RELATION", `Relation "${rel}" is not in the allowlist (${[...allowedRelations].join(", ")})`);
        } else {
          relations.add(rel);
        }
      }
      if (key === "FuncCall") {
        const parts = stringList((value as { funcname?: unknown[] }).funcname);
        const name = parts[parts.length - 1] ?? "";
        const fschema = parts.length > 1 ? parts[0] : undefined;
        if (fschema && fschema !== "pg_catalog" && fschema !== schema) {
          add("FORBIDDEN_FUNCTION", `Function schema "${fschema}" is not allowed`);
        } else if (!allowedFunctions.has(name)) {
          add("FORBIDDEN_FUNCTION", `Function "${name}" is not in the allowlist`);
        } else {
          functions.add(name);
        }
      }
      if (key === "TypeCast") {
        const names = stringList((value as { typeName?: { names?: unknown[] } }).typeName?.names);
        const typ = names[names.length - 1] ?? "";
        if (isForbiddenCast(typ)) add("FORBIDDEN_CAST", `Cast to "${typ}" is not allowed`);
      }
      visit(value);
    }
  };

  // Root-level WITH: a non-recursive CTE can only see the CTEs defined before it, so a name is
  // added to scope only after its own body was checked.
  const rootSelect = root.SelectStmt as Record<string, unknown>;
  const withClause = rootSelect.withClause as { WithClause?: unknown } | undefined;
  const w = (withClause && "WithClause" in withClause ? withClause.WithClause : withClause) as
    | { recursive?: boolean; ctes?: unknown[] }
    | undefined;
  if (w) {
    if (w.recursive && !policy.allowRecursiveCte) add("RECURSIVE_CTE", "WITH RECURSIVE is not allowed");
    for (const cte of w.ctes ?? []) {
      const c = (cte as { CommonTableExpr?: { ctename?: string; ctequery?: Record<string, unknown> } }).CommonTableExpr;
      if (!c) continue;
      const qType = c.ctequery ? Object.keys(c.ctequery)[0] : undefined;
      if (qType !== "SelectStmt") {
        add("DATA_MODIFYING_CTE", `CTE "${c.ctename}" must be a SELECT, got ${qType}`);
      } else {
        // A recursive CTE references itself, so its name is in scope for its own body.
        if (w.recursive && policy.allowRecursiveCte && c.ctename) cteNames.add(c.ctename);
        visit(c.ctequery);
      }
      if (c.ctename) cteNames.add(c.ctename);
    }
  }
  const { withClause: _ignored, ...body } = rootSelect;
  void _ignored;
  visit({ SelectStmt: body });

  if (violations.length) return blocked(violations);
  return { allowed: true, sql: trimmed, relations: [...relations], functions: [...functions], reasons: [] };
}
