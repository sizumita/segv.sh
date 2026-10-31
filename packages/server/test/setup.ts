import { applyD1Migrations, type D1Migration } from "cloudflare:test";
import { env } from "cloudflare:workers";

// Idempotent: applyD1Migrations skips migrations already recorded in d1_migrations.
await applyD1Migrations(
  env.DB,
  (env as unknown as { TEST_MIGRATIONS: D1Migration[] }).TEST_MIGRATIONS,
);
