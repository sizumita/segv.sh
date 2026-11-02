// The screens of a pull request in a comment on it (docs/DEVELOPMENT.md, "Screenshots in pull requests").
//
//   node .github/scripts/screenshots.mjs ui-changed < paths   prints ui=true or ui=false: whether any of the paths
//                                                            (one per line) changes what the apps show
//   node .github/scripts/screenshots.mjs preview <dir>       prints the comment for the screenshots in <dir>, as the
//                                                            end-to-end test leaves them (E2E_SHOTS), without posting
//   node .github/scripts/screenshots.mjs post <dir>          what the Screenshots workflow runs (screenshots.yml)
//
// `post` reads the screenshots that the CI run left as artifacts, and runs with a token that can write: it treats
// them as data from anyone, a fork included. It finds the pull request through the API by the run's head commit, and
// does nothing unless that pull request changes what the apps show. It takes only PNG files named as the end-to-end
// test names them (apps/web/test/e2e/lib/harness.mjs), and builds every word of the comment from those names. It
// commits the files, with no parent, to refs/screenshots/pr-<number> (outside refs/heads, so that no clone fetches
// them), and the comment shows them from that commit. Environment: GITHUB_TOKEN, GITHUB_REPOSITORY, RUN_ID, HEAD_SHA,
// HEAD_REPO and HEAD_BRANCH (the workflow_run event's).
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Paths whose changes show in the apps' screens, or in how the end-to-end tests take them. */
const UI = [
  /^packages\/(ui|engine)\//,
  /^apps\/web\/(src|public|adapters)\//,
  /^apps\/web\/(vite\.config\.ts|wrangler\.jsonc)$/,
  /^apps\/web\/test\/e2e\//,
  /^apps\/desktop\//,
  /^(Cargo\.lock|pnpm-lock\.yaml)$/,
  /^\.github\/workflows\/(ci|screenshots)\.yml$/,
  /^\.github\/scripts\/screenshots\.mjs$/,
];

/** The groups of screenshots: the directory that the end-to-end test writes, and the CI job that runs it. */
const GROUPS = [
  { dir: "web", title: "Web app", how: "headless Chromium", job: "End-to-end test" },
  {
    dir: "windows",
    title: "Windows app",
    how: "the installed app, driven through WebView2",
    job: "End-to-end test (Windows app)",
  },
];
const VARIANTS = ["light", "dark", "narrow"];
const NAME = /^(\d{2})-([a-z0-9]+(?:-[a-z0-9]+)*)\.(light|dark|narrow)\.png$/;
const MAX_FILES = 100;
const MAX_BYTES = 4 << 20;
const MARKER = "<!-- segv.sh screenshots -->";
const HEIGHT = 160;

const uiChanged = (paths) => paths.some((p) => UI.some((re) => re.test(p)));

/** A PNG file of at most MAX_BYTES and 4096 × 4096 pixels. */
function isPng(path) {
  const size = statSync(path).size;
  if (size < 24 || size > MAX_BYTES) return false;
  const b = readFileSync(path);
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (!sig.every((x, i) => b[i] === x) || b.toString("latin1", 12, 16) !== "IHDR") return false;
  const w = b.readUInt32BE(16);
  const h = b.readUInt32BE(20);
  return w > 0 && h > 0 && w <= 4096 && h <= 4096;
}

/** The screens of each group in `dir`: [{ group, screens: [{ n, title, files: { variant: name } }] }]. */
function collect(dir) {
  let count = 0;
  const found = [];
  for (const group of GROUPS) {
    const at = join(dir, group.dir);
    let names = [];
    try {
      names = readdirSync(at).sort();
    } catch {
      /* none */
    }
    const screens = new Map();
    for (const name of names) {
      const m = NAME.exec(name);
      if (!m || !statSync(join(at, name)).isFile() || !isPng(join(at, name))) {
        console.log(`skipped ${group.dir}/${name.slice(0, 80)}`);
        continue;
      }
      if (++count > MAX_FILES) throw new Error(`more than ${MAX_FILES} screenshots`);
      const key = `${m[1]}-${m[2]}`;
      if (!screens.has(key))
        screens.set(key, { n: m[1], title: m[2].replace(/-/g, " "), files: {} });
      screens.get(key).files[m[3]] = name;
    }
    found.push({ group, screens: [...screens.values()] });
  }
  return found;
}

const VERDICT = {
  success: "✅ passed",
  failure: "❌ failed",
  cancelled: "⏹️ cancelled",
  skipped: "⏭️ skipped",
  timed_out: "⌛ timed out",
};

/** The comment: a table of screens for each group, with each image a link to its full size. */
function body(found, { url, sha, runUrl, jobs }) {
  const of = sha ? ` of \`${sha.slice(0, 7)}\`` : "";
  const run = runUrl ? ` ([run](${runUrl}))` : "";
  const lines = [
    MARKER,
    "## Screenshots",
    "",
    `From the end-to-end tests${of}${run}, with throwaway accounts on a local deployment.`,
    "",
  ];
  for (const { group, screens } of found) {
    const conclusion = jobs?.[group.job];
    if (!screens.length && !conclusion) continue;
    const verdict = conclusion ? ` · end-to-end test ${VERDICT[conclusion] ?? conclusion}` : "";
    const open = conclusion === "failure" || group === GROUPS[0] ? " open" : "";
    lines.push(
      `<details${open}><summary><b>${group.title}</b> (${group.how})${verdict} · ${screens.length} screen${screens.length === 1 ? "" : "s"}</summary>`,
      "",
    );
    if (!screens.length) {
      lines.push("No screenshots: the test stopped before the first one.", "", "</details>", "");
      continue;
    }
    const variants = VARIANTS.filter((v) => screens.some((s) => s.files[v]));
    lines.push(`| | ${variants.join(" | ")} |`, `| --- |${" --- |".repeat(variants.length)}`);
    for (const s of screens) {
      const cells = variants.map((v) => {
        const name = s.files[v];
        if (!name) return "";
        const src = url(`${group.dir}/${name}`);
        return `<a href="${src}"><img src="${src}" height="${HEIGHT}" alt="${s.title}, ${v}"></a>`;
      });
      // 99-failed-<device>: that device's page when a step failed.
      const title =
        s.n === "99" ? `**${s.title.replace(/^failed /, "")}**, at the failure` : `**${s.title}**`;
      lines.push(`| ${title} | ${cells.join(" | ")} |`);
    }
    lines.push("", "</details>", "");
  }
  return lines.join("\n");
}

/** A call of GitHub's REST API: a GET, or the request of `write` (its method and JSON body). */
async function api(path, write) {
  const r = await fetch(`https://api.github.com/${path}`, {
    ...write,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      "x-github-api-version": "2022-11-28",
      ...(write ? { "content-type": "application/json" } : {}),
    },
  });
  if (!r.ok) throw new Error(`${write?.method ?? "GET"} ${path}: ${r.status} ${await r.text()}`);
  return r.json();
}

/** Every item of a list that the API pages. */
async function all(path) {
  const items = [];
  for (let page = 1; ; page++) {
    const sep = path.includes("?") ? "&" : "?";
    const got = await api(`${path}${sep}per_page=100&page=${page}`);
    const list = Array.isArray(got) ? got : got.jobs;
    items.push(...list);
    if (list.length < 100) return items;
  }
}

/** Commits the screenshots, with no parent, to refs/screenshots/pr-<n>, and returns the commit. */
function push(found, dir, repo, n) {
  const work = mkdtempSync(join(tmpdir(), "screens-"));
  for (const { group, screens } of found)
    for (const s of screens)
      for (const name of Object.values(s.files)) {
        mkdirSync(join(work, group.dir), { recursive: true });
        copyFileSync(join(dir, group.dir, name), join(work, group.dir, name));
      }
  const auth = Buffer.from(`x-access-token:${process.env.GITHUB_TOKEN}`).toString("base64");
  const git = (...args) =>
    execFileSync("git", args, {
      cwd: work,
      encoding: "utf8",
      env: {
        ...process.env,
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "http.https://github.com/.extraheader",
        GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${auth}`,
        GIT_AUTHOR_NAME: "github-actions[bot]",
        GIT_AUTHOR_EMAIL: "41898282+github-actions[bot]@users.noreply.github.com",
        GIT_COMMITTER_NAME: "github-actions[bot]",
        GIT_COMMITTER_EMAIL: "41898282+github-actions[bot]@users.noreply.github.com",
      },
    }).trim();
  git("init", "-q");
  git("add", "-A");
  git("commit", "-q", "-m", `Screenshots of pull request #${n}`);
  git("push", "-q", "--force", `https://github.com/${repo}.git`, `HEAD:refs/screenshots/pr-${n}`);
  return git("rev-parse", "HEAD");
}

async function post(dir) {
  const { GITHUB_REPOSITORY: repo, RUN_ID: run, HEAD_SHA: sha, HEAD_REPO: headRepo } = process.env;
  const branch = process.env.HEAD_BRANCH;
  const owner = headRepo.split("/")[0];
  const pulls = await api(
    `repos/${repo}/pulls?state=open&head=${encodeURIComponent(`${owner}:${branch}`)}`,
  );
  const pr = pulls.find((p) => p.head.sha === sha);
  if (!pr) return console.log(`no open pull request has ${sha} as its head`);
  const files = await all(`repos/${repo}/pulls/${pr.number}/files`);
  if (!uiChanged(files.map((f) => f.filename)))
    return console.log(`#${pr.number} changes nothing that the apps show`);
  const found = collect(dir);
  const jobs = Object.fromEntries(
    (await all(`repos/${repo}/actions/runs/${run}/jobs`)).map((j) => [j.name, j.conclusion]),
  );
  const any = found.some((g) => g.screens.length);
  const commit = any ? push(found, dir, repo, pr.number) : "";
  const text = body(found, {
    url: (path) => `https://raw.githubusercontent.com/${repo}/${commit}/${path}`,
    sha,
    runUrl: `https://github.com/${repo}/actions/runs/${run}`,
    jobs,
  });
  const comments = await all(`repos/${repo}/issues/${pr.number}/comments`);
  const mine = comments.find(
    (c) => c.user?.login === "github-actions[bot]" && c.body?.startsWith(MARKER),
  );
  const payload = JSON.stringify({ body: text });
  if (mine)
    await api(`repos/${repo}/issues/comments/${mine.id}`, { method: "PATCH", body: payload });
  else await api(`repos/${repo}/issues/${pr.number}/comments`, { method: "POST", body: payload });
  console.log(
    `${mine ? "updated" : "posted"} the screenshots of #${pr.number} (${commit || "none"})`,
  );
}

const [command, dir] = process.argv.slice(2);
if (command === "ui-changed") {
  const paths = readFileSync(0, "utf8").split("\n").filter(Boolean);
  console.log(`ui=${uiChanged(paths)}`);
} else if (command === "preview" && dir) {
  console.log(body(collect(dir), { url: (path) => join(dir, path) }));
} else if (command === "post" && dir) {
  await post(dir);
} else {
  console.error("usage: screenshots.mjs ui-changed < paths | preview <dir> | post <dir>");
  process.exit(2);
}
