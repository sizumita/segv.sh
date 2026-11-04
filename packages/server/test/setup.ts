import { applyD1Migrations, type D1Migration } from "cloudflare:test";
import { env } from "cloudflare:workers";

// Idempotent: applyD1Migrations skips migrations already recorded in d1_migrations. Every database of the directory
// gets the same schema (docs/PROTOCOL.md §9.6): the log database and the two user databases.
const migrations = (env as unknown as { TEST_MIGRATIONS: D1Migration[] }).TEST_MIGRATIONS;
for (const db of [env.DB, env.DB1, env.DIRLOG]) await applyD1Migrations(db, migrations);
