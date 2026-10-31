// Checks the rules of the workspace (docs/DEVELOPMENT.md, "Workspace") that pnpm does not enforce by itself:
//  1. every dependency names "catalog:" or, for a workspace package, "workspace:*" (catalogMode: strict refuses a
//     conflicting `pnpm add`, but not a version written into a package.json by hand);
//  2. dependencies between workspace packages go only the ways listed in ALLOWED, and apps depend on no other app;
//  3. no package under packages/ depends on a platform's SDK: that code belongs to the app of that platform;
//  4. every package declares each package that its files import. pnpm hoists nothing, but Node also finds the
//     workspace root's own dependencies from every directory, so an undeclared import can still work by accident.
//
//   node scripts/check-workspace.mjs
import { readdirSync, readFileSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import { join, relative } from "node:path";

const ROOT = join(import.meta.dirname, "..");

/** The workspace packages that each package under packages/ may depend on. */
const ALLOWED = {
  "@segv/protocol": [],
  "@segv/engine": ["@segv/protocol"],
  "@segv/server": ["@segv/protocol"],
  "@segv/ui": ["@segv/engine", "@segv/protocol"],
};
/** Platform SDKs, which only apps may depend on. */
const PLATFORM_SDKS = [/^@capacitor\//, /^@capacitor-community\//, /^@ionic\//, /^@tauri-apps\//];
/** Imports that no package.json declares: runtime modules and the parts of a package that come with another one. */
const PROVIDED = [/^node:/, /^cloudflare:/, /^workerd:/];
/** Files that are generated (and declare modules that do not exist). */
const GENERATED = new Set(["worker-configuration.d.ts"]);
const FIELDS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
const SKIP_DIRS = new Set([
  "node_modules",
  "dist",
  "server",
  "tmp",
  ".wrangler",
  "target",
  "ios",
  "android",
]);

const errors = [];
const fail = (where, message) => errors.push(`${where}: ${message}`);

const workspaceYaml = readFileSync(join(ROOT, "pnpm-workspace.yaml"), "utf8");
const globs = [...workspaceYaml.matchAll(/^packages:\n((?:\s+- .+\n)+)/gm)]
  .flatMap((m) => m[1].split("\n"))
  .map((l) => l.trim().replace(/^- /, ""))
  .filter(Boolean);
const dirs = [
  ".",
  ...globs.flatMap((g) => {
    if (!g.endsWith("/*")) throw new Error(`unsupported packages glob: ${g}`);
    const base = g.slice(0, -2);
    return readdirSync(join(ROOT, base))
      .map((d) => join(base, d))
      .filter((d) => statSync(join(ROOT, d, "package.json"), { throwIfNoEntry: false }));
  }),
];
const pkgs = dirs.map((dir) => ({
  dir,
  json: JSON.parse(readFileSync(join(ROOT, dir, "package.json"), "utf8")),
}));
const names = new Set(pkgs.map((p) => p.json.name));

/** Source files of a package: everything except build output, native projects and nested packages. */
function* files(dir, top = dir) {
  for (const entry of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".")) continue;
      if (dir === "." && (globs.some((g) => path === g.slice(0, -2)) || entry.name === "docs"))
        continue;
      if (path !== top && statSync(join(ROOT, path, "package.json"), { throwIfNoEntry: false }))
        continue;
      yield* files(path, top);
    } else if (/\.(?:[cm]?[jt]sx?)$/.test(entry.name) && !GENERATED.has(entry.name)) yield path;
  }
}

/** The packages a file imports (statically, dynamically, or for types). */
function importsOf(text) {
  const code = text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/(?!\/\s*<reference).*$/gm, "");
  const found = [];
  for (const re of [
    /^\s*(?:import|export)\s[^;]*?\sfrom\s*["']([^"']+)["']/gm,
    /^\s*import\s*["']([^"']+)["']/gm,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
    /\/\/\/\s*<reference\s+types=["']([^"']+)["']/g,
  ]) {
    for (const m of code.matchAll(re)) found.push(m[1]);
  }
  return found
    .filter((s) => !s.startsWith(".") && !s.startsWith("/"))
    .map((s) => s.replace(/\?.*$/, ""))
    .filter((s) => !PROVIDED.some((re) => re.test(s)) && !builtinModules.includes(s))
    .map((s) => (s.startsWith("@") ? s.split("/").slice(0, 2).join("/") : s.split("/")[0]));
}

for (const { dir, json } of pkgs) {
  const where = dir === "." ? "package.json" : `${dir}/package.json`;
  const declared = new Set();
  for (const field of FIELDS) {
    for (const [dep, spec] of Object.entries(json[field] ?? {})) {
      declared.add(dep);
      // 1. catalog: or workspace:*
      if (names.has(dep)) {
        if (spec !== "workspace:*") fail(where, `${field}.${dep} is "${spec}", not "workspace:*"`);
      } else if (spec !== "catalog:") fail(where, `${field}.${dep} is "${spec}", not "catalog:"`);
      if (field === "peerDependencies") continue;
      // 2. direction
      if (names.has(dep)) {
        if (dir.startsWith("packages/") && !(ALLOWED[json.name] ?? []).includes(dep))
          fail(
            where,
            `${json.name} may not depend on ${dep} (see ALLOWED in scripts/check-workspace.mjs)`,
          );
        if (dir.startsWith("packages/") && !(json.name in ALLOWED))
          fail(where, `${json.name} is missing from ALLOWED in scripts/check-workspace.mjs`);
        const target = pkgs.find((p) => p.json.name === dep);
        if (target?.dir.startsWith("apps/")) fail(where, `nothing may depend on an app (${dep})`);
      }
      // 3. platform SDKs
      if (dir.startsWith("packages/") && PLATFORM_SDKS.some((re) => re.test(dep)))
        fail(where, `${dep} is a platform SDK: only an app may depend on it`);
    }
  }
  // 4. declared imports
  for (const file of files(dir)) {
    for (const dep of importsOf(readFileSync(join(ROOT, file), "utf8"))) {
      if (dep !== json.name && !declared.has(dep))
        fail(relative(ROOT, join(ROOT, file)), `imports ${dep}, which ${where} does not declare`);
    }
  }
}

if (errors.length) {
  console.error(errors.join("\n"));
  console.error(`\n${errors.length} problem(s). The rules: docs/DEVELOPMENT.md, "Workspace".`);
  process.exit(1);
}
console.log(`workspace ok: ${pkgs.length} packages`);
