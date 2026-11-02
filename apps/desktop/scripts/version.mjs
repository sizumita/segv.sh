// Prints the desktop app's version and build number for a build of HEAD (docs/DEVELOPMENT.md, "Releases"), as
// `version=…` and `build=…` lines for $GITHUB_OUTPUT:
//
//   node scripts/version.mjs release v1.2.3    the release of that tag: version 1.2.3
//   node scripts/version.mjs canary            a Canary build: a prerelease of the next version, 1.2.4-canary.N
//
// The next version is the last release tag before HEAD (vX.Y.Z) with its patch raised, or tauri.conf.json's version
// when that is higher (raise it there to make the next release a minor or a major one). N counts the commits since
// that tag, so that every Canary build sorts above the release before it and below the release after it, by semver.
// The build number, CFBundleVersion on macOS, counts the commits of HEAD: it grows with every build of either kind.
// It needs the whole history: a shallow clone is refused.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const RELEASE = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const git = (...a) => execFileSync("git", a, { encoding: "utf8" }).trim();
const fail = (m) => {
  console.error(`version: ${m}`);
  process.exit(1);
};

/** [major, minor, patch] of "X.Y.Z" or "vX.Y.Z". */
const parse = (v) => v.replace(/^v/, "").split(".").map(Number);
const compare = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];

if (git("rev-parse", "--is-shallow-repository") === "true")
  fail("the clone is shallow: fetch the whole history (actions/checkout with fetch-depth: 0)");
const build = git("rev-list", "--count", "HEAD");
const [kind, tag] = process.argv.slice(2);

if (kind === "release") {
  if (!RELEASE.test(tag ?? "")) fail(`a release needs a tag vX.Y.Z, not ${JSON.stringify(tag)}`);
  if (git("rev-parse", `${tag}^{commit}`) !== git("rev-parse", "HEAD")) fail(`${tag} is not HEAD`);
  console.log(`version=${tag.slice(1)}\nbuild=${build}`);
} else if (kind === "canary") {
  const conf = JSON.parse(
    readFileSync(join(import.meta.dirname, "../src-tauri/tauri.conf.json"), "utf8"),
  );
  if (!/^\d+\.\d+\.\d+$/.test(conf.version))
    fail(`tauri.conf.json's version is not X.Y.Z: ${conf.version}`);
  const last = git("tag", "--merged", "HEAD", "--list", "v*")
    .split("\n")
    .filter((t) => RELEASE.test(t))
    .sort((a, b) => compare(parse(b), parse(a)))[0];
  let next = parse(conf.version);
  if (last) {
    const [x, y, z] = parse(last);
    if (compare([x, y, z + 1], next) > 0) next = [x, y, z + 1];
  }
  const n = git("rev-list", "--count", last ? `${last}..HEAD` : "HEAD");
  console.log(`version=${next.join(".")}-canary.${n}\nbuild=${build}`);
} else {
  fail("usage: version.mjs release vX.Y.Z | version.mjs canary");
}
