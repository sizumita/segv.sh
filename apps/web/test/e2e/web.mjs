// The web app in Chromium: what only the whole system shows, the production Worker with its Durable Objects, D1 and R2
// under `wrangler dev`, the UI that it renders, real passkeys (virtual authenticators with PRF) and several devices at
// once. The rules of the protocol are tested where they are enforced (packages/*/test); this run checks that they hold
// together, and takes a screenshot of each screen.
import { check, note, problems, step, T, unwatch } from "./lib/harness.mjs";
import {
  accept,
  closeImage,
  closeMembers,
  device,
  inList,
  newConversation,
  notSeen,
  open,
  openImage,
  openMembers,
  openRequest,
  ready,
  register,
  saveFile,
  seen,
  seenImage,
  send,
  sendFile,
  sendImage,
  settings,
  signInWithPasskey,
  signedOut,
  unlockWithCode,
} from "./lib/ui.mjs";

export async function web({ base, browser, shots, P, Wire }) {
  const startEra = P.era(Date.now());
  const sfx = Date.now().toString(36).slice(-4);
  const H = { alice: `alice_${sfx}`, bob: `bob_${sfx}`, carol: `carol_${sfx}` };
  const team = `team ${sfx}`;
  // Every plaintext sent: none may appear in the public data.
  const t1 = `こんにちは bob — secret-1 ${sfx} 🙂`;
  const t2 = `返信です secret-2 ${sfx}`;
  const t3 = `group hello secret-3 ${sfx}`;
  const t4 = `carol here secret-4 ${sfx}`;
  const t5 = `after removal secret-5 ${sfx}`;
  const t6 = `from alice's second device secret-6 ${sfx}`;
  const fileName = `minutes-${sfx}.txt`;
  const fileText = `議事録 secret-file ${sfx}\n`;
  const secrets = [t1, t2, t3, t4, t5, t6, fileName, fileText];
  const screen = (d, title) => shots.screen(d.page, title);
  let codeAlice = "";

  await step("CSP and security headers on the HTML and the API", async () => {
    const r = await fetch(`${base}/`);
    const csp = r.headers.get("content-security-policy") ?? "";
    check(/script-src[^;]*'nonce-/.test(csp), `no nonce CSP: ${csp}`);
    check(
      csp.includes("object-src 'none'") && csp.includes("frame-ancestors 'none'"),
      `weak CSP: ${csp}`,
    );
    check(r.headers.get("referrer-policy") === "no-referrer", "referrer-policy");
    const api = await fetch(`${base}/api/v2/params`);
    check(/^\d+$/.test(api.headers.get("x-segv-now") ?? ""), "x-segv-now on the API");
    check(api.headers.get("x-content-type-options") === "nosniff", "nosniff on the API");
  });

  const A = await device(browser, base, "alice");
  const B = await device(browser, base, "bob");
  const C = await device(browser, base, "carol");

  await step("three accounts with passkeys (PRF); carol's device remembers her", async () => {
    await signedOut(A);
    await screen(A, "signed out");
    codeAlice = await register(A, H.alice, { atCode: () => screen(A, "recovery code") });
    await screen(A, "no conversations");
    await register(B, H.bob);
    await register(C, H.carol, { remember: true });
  });

  await step(
    "1:1: reading a request does not accept it; text both ways, a reaction, an image, a file",
    async () => {
      await newConversation(A, H.bob, undefined, { atForm: () => screen(A, "new conversation") });
      await send(A, t1);
      await openRequest(B, `@${H.alice}`, t1);
      await screen(B, "request");
      await accept(B);
      await send(B, t2);
      await seen(A, t2);
      const mine = B.page.locator(".thread .m", { hasText: t1 }).first();
      await mine.hover();
      await mine
        .getByRole("toolbar")
        .getByRole("button", { name: "add a reaction" })
        .click({ timeout: T });
      const picker = B.page.getByRole("dialog", { name: "add a reaction" });
      await picker.getByRole("textbox", { name: "search emoji" }).fill("thumbs up");
      const thumbs = picker.getByRole("button", { name: "thumbs up", exact: true });
      await thumbs.waitFor({ timeout: T });
      await screen(B, "reaction picker");
      await thumbs.click({ timeout: T });
      await mine.locator(".react.mine", { hasText: "👍 1" }).waitFor({ timeout: T });
      const theirs = A.page.locator(".thread .m", { hasText: t1 }).first();
      await theirs.locator(".react", { hasText: "👍 1" }).waitFor({ timeout: T });
      await sendImage(A, `img ${sfx}`);
      await seenImage(B);
      await sendFile(B, fileName, fileText, { atMenu: () => screen(B, "attach menu") });
      const saved = await saveFile(A, fileName);
      check(saved === fileText, `alice saved ${JSON.stringify(saved)}`);
      await screen(A, "conversation");
      await openImage(A);
      await screen(A, "image");
      await closeImage(A);
    },
  );

  await step("a group of three, named at creation", async () => {
    await newConversation(A, `${H.bob}, ${H.carol}`, team);
    await send(A, t3);
    await open(B, team); // alice is bob's contact now: not a request
    await openRequest(C, team, t3);
    await accept(C);
    await seen(B, t3);
    await send(C, t4);
    await seen(A, t4);
    await seen(B, t4);
    await openMembers(A);
    await screen(A, "group members");
  });

  await step("removing a member cuts them off, and moves the group to their archives", async () => {
    const row = A.page.locator("aside.members li", { hasText: H.carol });
    await row.getByRole("button", { name: "remove" }).click();
    await row.locator(".confirm").getByRole("button", { name: "remove" }).click();
    await seen(A, `removed @${H.carol}`);
    await seen(C, "removed you");
    await C.page.getByText("you are no longer a member").waitFor({ timeout: T });
    await inList(C, "archives", team);
    await screen(C, "removed from a group");
    await closeMembers(A);
    await send(A, t5);
    await seen(B, t5);
    await notSeen(C, t5);
  });

  await step(
    "a remembered device stays signed in across a reload, until it signs out",
    async () => {
      await C.page.reload({ waitUntil: "load" });
      await ready(C);
      await C.page.getByText(`@${H.carol}`).first().waitFor({ timeout: T });
      await (await settings(C)).getByRole("button", { name: "sign out" }).click();
      await signedOut(C);
      await C.page.reload({ waitUntil: "load" });
      await signedOut(C);
    },
  );

  await step(
    "a device that does not remember signs out on reload; a passkey restores it",
    async () => {
      await A.page.reload({ waitUntil: "load" });
      await signInWithPasskey(A);
      await open(A, `@${H.bob}`);
      await seen(A, t1);
      await seen(A, t2);
      await seenImage(A);
    },
  );

  await step(
    "a new device: the recovery code restores the history, then it adds a passkey",
    async () => {
      const A2 = await device(browser, base, "alice-2");
      await unlockWithCode(A2, codeAlice, {
        atForm: () => screen(A2, "unlock with the recovery code"),
      });
      await open(A2, team);
      await seen(A2, t3);
      await seen(A2, t4);
      const prefs = await settings(A2);
      await prefs.getByRole("button", { name: "add passkey" }).click();
      await prefs.getByText("passkey added.").waitFor({ timeout: T });
      await screen(A2, "settings");
      await prefs.getByRole("button", { name: "sign out" }).click();
      await signInWithPasskey(A2);
      await open(A2, `@${H.bob}`);
      await seen(A2, t2);
      // What the second device sends reaches the first one and bob.
      await send(A2, t6);
      await seen(A, t6);
      await open(B, `@${H.alice}`);
      await seen(B, t6);
      unwatch(A2.page);
      await A2.ctx.close();
    },
  );

  await step("the public data verifies and leaks no plaintext", async () => {
    const getBytes = async (path) => {
      const r = await fetch(`${base}${path}`);
      check(r.ok, `${path}: ${r.status}`);
      return new Uint8Array(await r.arrayBuffer());
    };
    /** Every closed batch of shard (E, 0), with each batch's root and the head chain verified (§9.1, §10.9). */
    const feedOf = async (E) => {
      const batches = [];
      let head = P.ZERO32;
      for (let after = 0; ;) {
        const page = Wire.decodeFeed(await getBytes(`/api/v2/feed/${E}/0?after=${after}`));
        for (const b of page.batches) {
          const leaves = [...b.rows]
            .sort((x, y) => Buffer.compare(Buffer.from(x.label), Buffer.from(y.label)))
            .map((r) => P.leafShard(E, r.label, b.t, r.cls, r.body));
          check(
            b.rows.length === b.n,
            `feed ${E}: batch ${b.t} has ${b.rows.length} rows, n = ${b.n}`,
          );
          check(
            P.equalBytes(P.mth(leaves), b.root),
            `feed ${E}: the root of batch ${b.t} does not verify`,
          );
          head = P.nextHead(P.shardCid(E, 0), head, b.t, b.n, b.root);
          check(P.equalBytes(head, b.head), `feed ${E}: the head chain breaks at batch ${b.t}`);
          batches.push(b);
          after = b.t;
        }
        if (!page.more) break;
      }
      return batches;
    };
    /** Every inbox row of era E (§10.5). */
    const inboxOf = async (E) => {
      const rows = [];
      for (let after = 0; ;) {
        const page = Wire.decodeInboxRead(await getBytes(`/api/v2/inbox/${E}/0?after=${after}`));
        rows.push(...page.rows);
        if (!page.more) break;
        after = page.rows.at(-1).rel;
      }
      return rows;
    };
    const needles = [...secrets, team, ...Object.values(H)].map((s) => Buffer.from(s, "utf8"));
    const clean = (what, bytes) => {
      const b = Buffer.from(bytes);
      for (const n of needles) check(!b.includes(n), `plaintext "${n}" visible in ${what}`);
    };
    const Enow = P.era(Date.now());
    // Shard feeds: roots, head chains, row sizes, no plaintext.
    let rows = 0;
    for (let E = startEra; E <= Enow; E++)
      for (const b of await feedOf(E))
        for (const r of b.rows) {
          rows++;
          check(P.BODY_LENS.includes(r.body.length), `row size ${r.body.length}`);
          clean(`a row of batch ${b.t}`, r.body);
        }
    check(rows > 0, "the feed holds no rows");
    // The deployment's checkpoints run: the latest one's head of this era's shard is in the feed's head chain (§9.5).
    const cid = P.shardCid(Enow, 0);
    const t0 = Date.now();
    for (;;) {
      const r = await fetch(`${base}/api/v2/ckpt/latest`);
      const ck = r.ok ? await r.json() : null;
      const h = ck?.heads?.find((x) => x.cid === cid)?.head;
      if (h) {
        const known = (await feedOf(Enow)).map((b) => P.b64u(b.head));
        check(
          known.includes(h),
          `checkpoint ${ck.q}: the head of ${cid} is not in the feed's head chain`,
        );
        break;
      }
      check(Date.now() - t0 < 150_000, "no checkpoint covered the shard within 150 s");
      await new Promise((res) => setTimeout(res, 2000));
    }
    // Inbox rows: the one size, no plaintext.
    let invites = 0;
    for (let E = startEra; E <= Enow; E++)
      for (const r of await inboxOf(E)) {
        invites++;
        check(r.body.length === P.INBOX_BODY_LEN, `invite size ${r.body.length}`);
        clean(`an invite of era ${E}`, r.body);
      }
    // bob's 1:1 invite and carol's group invite; bob's group J is a WELCOME in his 1:1 with alice (§6.12 step 1).
    check(invites === 2, `expected 2 invites, got ${invites}`);
    // The directory's public log: three registrations.
    const r = await fetch(`${base}/api/v2/dirlog?after=0&limit=1000`);
    check(r.ok, `/api/v2/dirlog: ${r.status}`);
    const log = await r.json();
    const users = log.entries.filter((x) => x.kind === 1).length;
    check(users === 3, `expected 3 user entries in the dirlog, got ${users}`);
    note(`data: ${rows} rows, ${invites} invites, ${log.entries.length} dirlog entries`);
  });

  await step("no page errors or CSP violations", async () => {
    check(problems.length === 0, problems.join("\n"));
  });
}
