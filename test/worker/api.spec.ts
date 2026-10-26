/** HTTP API tests (docs/PROTOCOL.md §4–§5) against test/worker/entry.ts inside workerd. */
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import * as P from "../../src/lib/proto";
import type { LogDO } from "../../src/server/log-do";
import {
  DIFF,
  ORIGIN,
  api,
  appendOk,
  badNonce,
  currentWindow,
  downloadVerified,
  errorOf,
  freshIp,
  getLog,
  head,
  jsonBytes,
  makeAccount,
  makeEpoch,
  makeMsg,
  need,
  nonceBetween,
  pageToHead,
  postPow,
  powHeader,
  randomInvRow,
  randomMsgRow,
  registerBody,
  registerOk,
  wireRows,
  type WireRow,
} from "./helpers";

const stub = () => (env.LOG as unknown as DurableObjectNamespace<LogDO>).getByName("global");
/** Random bytes of any length (getRandomValues is limited to 64 KiB per call). */
function bigRandom(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) out.set(P.random(Math.min(65536, n - o)), o);
  return out;
}
/** workerd's caches.default (the DOM lib typing does not know it). */
const edgeCache = (): Cache => (caches as unknown as { default: Cache }).default;

const HSTS = "max-age=63072000; includeSubDomains";

const expectApiHeaders = (res: Response) => {
  expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  expect(res.headers.get("strict-transport-security")).toBe(HSTS); // ORIGIN is https
};

describe("GET /api/params", () => {
  it("reports clock, window, difficulties and limits", async () => {
    const before = Date.now();
    const res = await api("/api/params");
    expect(res.status).toBe(200);
    expectApiHeaders(res);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("content-type")).toMatch(/^application\/json/);
    const p = (await res.json()) as { now: number; window: number; pow: Record<string, number>; limits: Record<string, number> };
    expect(p.now).toBeGreaterThanOrEqual(before - 1000);
    expect(p.window).toBe(Math.floor(p.now / P.POW_WINDOW_MS));
    expect(p.pow).toEqual(DIFF);
    expect(p.limits).toEqual({ batch: 40, blobMax: P.BLOB_MAX });
  });

  it("rejects other methods and unknown paths", async () => {
    const res = await api("/api/params", { method: "POST" });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("GET");
    expect(await errorOf(res)).toMatch(/method/);
    const nf = await api("/api/nope");
    expect(nf.status).toBe(404);
    expectApiHeaders(nf);
    expect(await errorOf(nf)).toBe("not found");
  });
});

describe("POST /api/register", () => {
  it("registers a user with passkey + recovery wraps as one atomic batch", async () => {
    const a = makeAccount();
    const before = await head();
    const seq = await registerOk(a);
    expect(seq).toBe(before.seq + 1);

    const { rows } = await getLog(before.seq, 10);
    const mine = rows.filter((r) => r.seq >= seq && r.seq <= seq + 2);
    expect(mine.map((r) => r.kind)).toEqual([1, 2, 2]);
    // kind 1: tag = userTag(uid), body = {bundle, sig} with the exact signed text
    expect(mine[0].tag).toBe(P.b64u(P.userTag(a.uid)));
    expect(JSON.parse(P.fromUtf8(P.fromB64u(mine[0].body)))).toEqual({ bundle: a.bundle, sig: a.sig });
    expect(P.verifyBundle(a.bundle, a.sig).uid).toBe(a.uidB64);
    // kind 2: tag = wrapTag(record), body = {record, sig}
    expect(mine[1].tag).toBe(P.b64u(P.wrapTag(a.passkey.record)));
    expect(JSON.parse(P.fromUtf8(P.fromB64u(mine[1].body)))).toEqual(a.passkey);
    expect(mine[2].tag).toBe(P.b64u(P.wrapTag(a.recovery.record)));

    // D1 index is up to date when /api/register returns (read-your-writes).
    const u = await api(`/api/users/${a.handle}`);
    expect(u.status).toBe(200);
    expectApiHeaders(u);
    expect(await u.json()).toEqual({ uid: a.uidB64, handle: a.handle, bundle: a.bundle, sig: a.sig, seq });

    // Passkey login path: wraps by credential id -> verify -> unwrap AK.
    const w = await api(`/api/wraps/${P.b64u(a.credId)}`);
    expect(w.status).toBe(200);
    const { wraps } = (await w.json()) as { wraps: { seq: number; uid: string; record: string; sig: string }[] };
    expect(wraps).toEqual([{ seq: seq + 1, uid: a.uidB64, record: a.passkey.record, sig: a.passkey.sig }]);
    const user = P.verifyBundle(a.bundle, a.sig);
    const rec = P.verifyWrap(wraps[0].record, wraps[0].sig, user.sigPk);
    expect(P.equalBytes(P.unwrapAK(rec, a.cred, user.sigPk), a.AK)).toBe(true);
    // Recovery id lookup + unlock with the recovery code's key.
    const r = (await (await api(`/api/wraps/${P.b64u(a.recId)}`)).json()) as { wraps: { record: string; sig: string }[] };
    expect(r.wraps).toHaveLength(1);
    const recW = P.verifyWrap(r.wraps[0].record, r.wraps[0].sig, user.sigPk);
    expect(P.equalBytes(P.unwrapAK(recW, a.rec, user.sigPk), a.AK)).toBe(true);
    // A wrap only opens with the secret it was made for (auth is bound into the seal context).
    expect(() => P.unwrapAK(rec, { sk: a.cred.sk, auth: P.random(32) }, user.sigPk)).toThrow();
    // uid filter (passkey login passes the WebAuthn userHandle).
    const own = (await (await api(`/api/wraps/${P.b64u(a.credId)}?uid=${a.uidB64}`)).json()) as { wraps: unknown[] };
    expect(own.wraps).toHaveLength(1);
    const other = (await (await api(`/api/wraps/${P.b64u(a.credId)}?uid=${P.b64u(P.random(16))}`)).json()) as { wraps: unknown[] };
    expect(other.wraps).toHaveLength(0);
  });

  it("400 on bundles with unusable keys", async () => {
    const a = makeAccount();
    const raw = JSON.parse(a.bundle) as Record<string, unknown>;
    // A small-order signing key is covered by the unit tests (it cannot produce a valid self-signature here).
    for (const over of [{ scan: P.b64u(new Uint8Array(32)) }, { kem: P.b64u(new Uint8Array(1216).fill(0xff)) }]) {
      const bundle = JSON.stringify({ ...raw, ...over });
      const sig = P.b64u(P.sign(P.bundleSigMsg(bundle), a.ident.sigSk));
      const res = await postPow("/api/register", "register", { bundle, sig, wraps: [a.passkey] });
      expect(res.status).toBe(400);
    }
  });

  it("409 on a taken handle or uid, and nothing is appended", async () => {
    const a = makeAccount();
    await registerOk(a);
    const h0 = await head();

    const sameHandle = makeAccount(a.handle);
    let res = await postPow("/api/register", "register", registerBody(sameHandle));
    expect(res.status).toBe(409);
    expect(await errorOf(res)).toMatch(/handle/);

    const sameUid = makeAccount(undefined, a.uid);
    res = await postPow("/api/register", "register", registerBody(sameUid));
    expect(res.status).toBe(409);
    expect(await errorOf(res)).toMatch(/uid|tag/);

    expect(await head()).toEqual(h0);
  });

  it("400 on a bad bundle signature", async () => {
    const a = makeAccount();
    const sig = P.fromB64u(a.sig);
    sig[0] ^= 1;
    const res = await postPow("/api/register", "register", { ...registerBody(a), sig: P.b64u(sig) });
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toMatch(/signature/);
    expect((await api(`/api/users/${a.handle}`)).status).toBe(404);
  });

  it("400 on a wrap signed by another key or for another uid", async () => {
    const a = makeAccount();
    const b = makeAccount();
    // b's record (b's uid, b's key)
    let res = await postPow("/api/register", "register", registerBody(a, [a.passkey, b.passkey]));
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toMatch(/uid/);
    // a's uid, signed by b's key
    const forged = P.makeWrap(a.uid, "passkey", P.random(16), P.credKem(P.random(32), P.random(16)), a.AK, b.ident, Date.now());
    res = await postPow("/api/register", "register", registerBody(a, [forged]));
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toMatch(/wraps\[0\]: bad signature/);
  });

  it("400 on malformed bodies", async () => {
    const a = makeAccount();
    const cases: unknown[] = [
      registerBody(a, []), // no wraps
      registerBody(a, [a.passkey, a.recovery, a.passkey, a.recovery, a.passkey]), // > 4
      registerBody(a, [a.passkey, a.passkey]), // duplicate record
      { ...registerBody(a), extra: 1 }, // unknown field
      { bundle: a.bundle, sig: a.sig }, // missing wraps
      { ...registerBody(a), bundle: a.bundle.replace('{"v":1,', '{"v":1, ') }, // non-canonical JSON
      { ...registerBody(a), bundle: a.bundle.replace(a.handle, "Bad-Handle") },
      { ...registerBody(a), wraps: [{ record: a.passkey.record, sig: a.passkey.sig, x: 1 }] },
      { ...registerBody(a), sig: 42 },
      [registerBody(a)],
    ];
    for (const body of cases) {
      const res = await postPow("/api/register", "register", body);
      expect(res.status, JSON.stringify(body).slice(0, 80)).toBe(400);
    }
    const notJson = await postPow("/api/register", "register", P.utf8("{not json"));
    expect(notJson.status).toBe(400);
    expect(await errorOf(notJson)).toBe("invalid JSON");
  });

  it("413 above 64 KiB (declared or actual)", async () => {
    const big = new Uint8Array(64 * 1024 + 1).fill(0x20);
    const res = await postPow("/api/register", "register", big);
    expect(res.status).toBe(413);
    // Chunked body without Content-Length: enforced while reading.
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        for (let i = 0; i < 17; i++) c.enqueue(new Uint8Array(4096).fill(0x20));
        c.close();
      },
    });
    const res2 = await api("/api/register", { method: "POST", body: stream, headers: { "x-segv-pow": "0.0" } });
    expect(res2.status).toBe(413);
  });
});

describe("POST /api/wraps", () => {
  it("adds a wrap for an existing user", async () => {
    const a = makeAccount();
    await registerOk(a);
    const credId = P.random(20);
    const cred = P.credKem(P.random(32), credId);
    const w = P.makeWrap(a.uid, "passkey", credId, cred, a.AK, a.ident, Date.now());
    const res = await postPow("/api/wraps", "wrap", w);
    expect(res.status, await res.clone().text()).toBe(200);
    const { seq } = (await res.json()) as { seq: number };
    const got = (await (await api(`/api/wraps/${P.b64u(credId)}`)).json()) as { wraps: { seq: number }[] };
    expect(got.wraps.map((x) => x.seq)).toEqual([seq]);
    // Same record again -> same tag -> 409
    const again = await postPow("/api/wraps", "wrap", w);
    expect(again.status).toBe(409);
  });

  it("404 for an unknown uid, 400 for a bad signature", async () => {
    const ghost = makeAccount();
    const res = await postPow("/api/wraps", "wrap", ghost.passkey);
    expect(res.status).toBe(404);
    expect(await errorOf(res)).toMatch(/unknown uid/);

    const a = makeAccount();
    await registerOk(a);
    const other = makeAccount();
    const forged = P.makeWrap(a.uid, "recovery", P.random(16), P.credKem(P.random(32), P.random(16)), a.AK, other.ident, Date.now());
    const bad = await postPow("/api/wraps", "wrap", forged);
    expect(bad.status).toBe(400);
    expect(await errorOf(bad)).toMatch(/signature/);
  });
});

describe("POST /api/append", () => {
  it("appends invites + messages; recipients find and open them", async () => {
    const alice = makeAccount();
    const bob = makeAccount();
    await registerOk(alice);
    await registerOk(bob);
    const ep = makeEpoch(alice, bob);
    const invites = [bob, alice].map((m) => P.makeInvite({ kemPk: m.ident.kemPk, scanPk: m.ident.scanPk }, ep.dText, ep.EK, ep.dsig));
    const msgs = [makeMsg(ep, alice, 0, "hello bob"), makeMsg(ep, alice, 1, "x".repeat(2000))];
    const h0 = await head();
    // One batch = invites + at most one kind-4 row; the second message is its own append.
    const seqs = [...(await appendOk([...invites, msgs[0]])), ...(await appendOk([msgs[1]]))];
    expect(seqs).toEqual([1, 2, 3, 4].map((i) => h0.seq + i));

    const { rows } = await getLog(h0.seq, 4);
    expect(rows.map((r) => r.kind)).toEqual([3, 3, 4, 4]);
    // Bob scans the invites like a client.
    const asRow = (r: WireRow) => ({ tag: P.fromB64u(r.tag), body: P.fromB64u(r.body) });
    const found = rows.filter((r) => r.kind === 3).map((r) => P.inviteViewKey(bob.ident.scanSk, bob.ident.scanPk, asRow(r)));
    expect(found.filter(Boolean)).toHaveLength(1);
    const inv = P.openInvite(bob.ident.kemSk, found.find(Boolean)!, asRow(rows[0]));
    expect(inv.dText).toBe(ep.dText);
    // ...and reads the message.
    const m = P.openMessage(ep.keys.mk, asRow(rows[2]));
    expect(m.payload.text).toBe("hello bob");
    expect(P.verifyMessageSig(asRow(rows[2]).tag, m.text, m.psig, alice.ident.sigPk)).toBe(true);
    expect(P.fromB64u(rows[3].body).length).toBe(P.MSG_BODY_LENS[1]); // 2000 chars -> 4096 class
  });

  it("409 on a used tag and the whole batch is rejected", async () => {
    const used = randomMsgRow();
    await appendOk([used]);
    const fresh = randomInvRow();
    const h0 = await head();
    const res = await postPow("/api/append", "append", { rows: wireRows([fresh, { ...randomMsgRow(), tag: used.tag }]) });
    expect(res.status).toBe(409);
    expect(await errorOf(res)).toMatch(/tag/);
    expect(await head()).toEqual(h0); // no partial rows
    // The fresh row was not stored: appending it alone now succeeds.
    expect(await appendOk([fresh])).toEqual([h0.seq + 1]);
  });

  it("400 on bad kinds, lengths, tags, encodings and batch sizes", async () => {
    const ok = wireRows([randomMsgRow()])[0];
    const inv = wireRows([randomInvRow()])[0];
    const b64 = (n: number) => P.b64u(P.random(n));
    const cases: [string, unknown][] = [
      ["kind 1", { rows: [{ ...ok, kind: 1 }] }],
      ["kind 2", { rows: [{ ...ok, kind: 2 }] }],
      ["kind 5", { rows: [{ ...ok, kind: 5 }] }],
      ["kind as string", { rows: [{ ...ok, kind: "4" }] }],
      ["short body", { rows: [{ ...ok, body: b64(100) }] }],
      ["body one byte long", { rows: [{ ...ok, body: b64(P.MSG_BODY_LENS[0] + 1) }] }],
      ["invite length for kind 4", { rows: [{ ...ok, body: b64(P.INV_BODY_LENS[0]) }] }],
      ["msg length for kind 3", { rows: [{ ...ok, kind: 3 }] }],
      ["15-byte tag", { rows: [{ ...ok, tag: b64(15) }] }],
      ["17-byte tag", { rows: [{ ...ok, tag: b64(17) }] }],
      ["padded base64", { rows: [{ ...ok, tag: P.b64u(P.random(16)).slice(0, 20) + "==" }] }],
      ["std base64 alphabet", { rows: [{ ...ok, tag: "+".repeat(22) }] }],
      ["non-canonical base64", { rows: [{ ...ok, tag: "A".repeat(21) + "B" }] }],
      ["duplicate tags in batch", { rows: [inv, inv] }],
      ["empty batch", { rows: [] }],
      ["41 rows", { rows: wireRows(Array.from({ length: 41 }, () => randomInvRow())) }],
      ["two kind-4 rows", { rows: wireRows([randomMsgRow(), randomMsgRow()]) }],
      ["two kind-4 rows among invites", { rows: wireRows([randomMsgRow(), randomInvRow(), randomMsgRow(P.MSG_BODY_LENS[2])]) }],
      ["extra row field", { rows: [{ ...ok, ts: 1 }] }],
      ["extra top-level field", { rows: [ok], x: 1 }],
      ["rows not array", { rows: ok }],
    ];
    const h0 = await head();
    for (const [name, body] of cases) {
      const res = await postPow("/api/append", "append", body);
      expect(res.status, name).toBe(400);
    }
    expect(await head()).toEqual(h0);
  });

  it("accepts a full batch of 40 invites, and one 16 KiB-class claim + 39 invites (under the 256 KiB cap)", async () => {
    expect(P.INV_BODY_LENS).toEqual([32 + 1120 + 24 + 2048 + 16]);
    const rows = Array.from({ length: 40 }, randomInvRow);
    const seqs = await appendOk(rows);
    expect(seqs).toHaveLength(40);
    expect(seqs[39] - seqs[0]).toBe(39);
    const biggest = [randomMsgRow(P.MSG_BODY_LENS[2]), ...Array.from({ length: 39 }, randomInvRow)];
    expect(jsonBytes({ rows: wireRows(biggest) }).length).toBeLessThan(256 * 1024);
    expect(await appendOk(biggest)).toHaveLength(40);
  });

  it("413 above 256 KiB", async () => {
    const res = await postPow("/api/append", "append", new Uint8Array(256 * 1024 + 1).fill(0x20));
    expect(res.status).toBe(413);
  });

  it("proof of work is priced by the request size; /api/params keeps reporting the base", async () => {
    const bytes = jsonBytes({ rows: wireRows(Array.from({ length: 40 }, randomInvRow)) });
    const required = need("append", bytes.length);
    expect(required).toBe(DIFF.append + Math.ceil(Math.log2(bytes.length / 4096)));
    expect(required).toBeGreaterThan(DIFF.append);
    const w = currentWindow();
    const h0 = await head();
    const cheap = await api("/api/append", {
      method: "POST",
      body: bytes,
      headers: { "x-segv-pow": `${w}.${nonceBetween("append", w, P.H(bytes), DIFF.append, required)}` },
    });
    expect(cheap.status).toBe(403);
    expect(await errorOf(cheap)).toMatch(new RegExp(`insufficient.*${required} bits`));
    expect(await head()).toEqual(h0);
    const paid = await api("/api/append", { method: "POST", body: bytes, headers: { "x-segv-pow": await powHeader("append", P.H(bytes), { bytes: bytes.length }) } });
    expect(paid.status).toBe(200);
    // Small bodies (<= 4 KiB) cost the base difficulty.
    expect(need("append", 4096)).toBe(DIFF.append);
    expect(((await (await api("/api/params")).json()) as { pow: unknown }).pow).toEqual(DIFF);
  });
});

describe("GET /api/log", () => {
  it("pages through the whole log; the hash chain verifies across pages", async () => {
    await appendOk([randomMsgRow(), randomInvRow()]);
    const small = await downloadVerified(3);
    const big = await downloadVerified(1000);
    expect(big.head.seq).toBeGreaterThanOrEqual(small.head.seq);
    expect(big.rows.slice(0, small.rows.length)).toEqual(small.rows);
    expect(small.pages).toBeGreaterThan(1);
  });

  it("defaults, empty tail, and parameter validation", async () => {
    const h = await head();
    const raw = await api(`/api/log?after=${h.seq}`);
    expectApiHeaders(raw);
    expect(raw.headers.get("cache-control")).toBe("no-store");
    expect(raw.headers.get("strict-transport-security")).toBe(HSTS);
    expect(raw.headers.get("content-type")).toMatch(/^application\/json/);
    const tail = await getLog(h.seq);
    expect(tail.rows).toEqual([]);
    expect(tail.head).toEqual(h);
    const all = await getLog(0); // default limit 1000 (and the body budget)
    expect(all.rows[0].seq).toBe(1);
    expect(all.rows.length).toBeLessThanOrEqual(1000);
    for (const q of ["after=-1", "after=x", "limit=0", "limit=1001", "after=1.5", "after=99999999999999999", "limit="]) {
      const res = await api(`/api/log?${q}`);
      expect(res.status, q).toBe(400);
    }
  });

  it("> 4 MiB of rows before a registration: pages are short, the client pages through to it", async () => {
    const h0 = await head();
    // 260 x 16 KiB-class messages (one kind-4 row per append) = 4.27 MB of bodies, then a registration.
    for (let i = 0; i < 260; i++) await appendOk([randomMsgRow(P.MSG_BODY_LENS[2])]);
    const victim = makeAccount();
    const seq = await registerOk(victim);

    const first = await getLog(h0.seq, 1000);
    const bytes = first.rows.reduce((n, r) => n + P.fromB64u(r.body).length, 0);
    expect(first.rows.length).toBeLessThan(260); // short page (byte budget) although more rows exist
    expect(first.rows.length).toBeGreaterThan(200);
    expect(bytes).toBeLessThanOrEqual(4 * 1024 * 1024);
    expect(first.head.seq).toBeGreaterThanOrEqual(seq + 2); // the head is current, beyond the page

    // Client loop: continue until the last row's seq >= head.seq, never stop on a short page.
    const { rows, sizes } = await pageToHead(h0.seq);
    expect(sizes.length).toBeGreaterThan(1);
    const reg = rows.find((r) => r.kind === 1 && r.tag === P.b64u(P.userTag(victim.uid)));
    expect(reg?.seq).toBe(seq);
    // From the start of the log too, with the chain verified.
    const all = await downloadVerified(1000);
    expect(all.rows.some((r) => r.seq === seq && r.kind === 1)).toBe(true);
  });

  it("pages below the head are immutable and edge-cached; the head is always the live one", async () => {
    await appendOk([randomMsgRow()]);
    await appendOk([randomMsgRow()]);
    const h = await head();
    const after = h.seq - 2;
    const url = `/api/log?after=${after}&limit=1`;
    const a = await api(url);
    expect(a.status).toBe(200);
    expect(a.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expectApiHeaders(a);
    const pa = (await a.json()) as { rows: WireRow[]; head: { seq: number; h: string } };
    expect(pa.rows.map((r) => r.seq)).toEqual([after + 1]);
    expect(pa.head).toEqual(h);

    // The page lands in caches.default under the canonical URL (put happens in waitUntil).
    const key = `${ORIGIN}/api/log?after=${after}&limit=1`;
    let cached: Response | undefined;
    for (let i = 0; i < 50 && !cached; i++) {
      cached = await edgeCache().match(key);
      if (!cached) await new Promise((r) => setTimeout(r, 20));
    }
    expect(cached, "page not cached").toBeDefined();
    expect(cached!.headers.get("x-segv-last-seq")).toBe(String(after + 1));
    expect(cached!.headers.get("x-segv-last-h")).toBe(pa.rows[0].h);
    await cached!.arrayBuffer();

    // A later request is served from the cache with the same rows and the CURRENT head. (The entry is
    // re-stored pretty-printed, so the raw text shows which path answered.)
    await edgeCache().put(
      key,
      new Response(JSON.stringify(pa.rows, null, 1), {
        headers: { "cache-control": "public, max-age=60", "x-segv-last-seq": String(after + 1), "x-segv-last-h": pa.rows[0].h },
      }),
    );
    await appendOk([randomMsgRow()]);
    const h2 = await head();
    const b = await api(`/api/log?limit=1&after=${after}&junk=1`); // same canonical key
    expect(b.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    const text = await b.text();
    expect(text).toContain("\n"); // served from the cache
    const pb = JSON.parse(text) as { rows: WireRow[]; head: { seq: number; h: string } };
    expect(pb.rows).toEqual(pa.rows);
    expect(pb.head).toEqual(h2);

    // A cache entry that does not belong to this log (e.g. a wiped dev database) is never served.
    const bogus = `${ORIGIN}/api/log?after=${after + 1}&limit=1`;
    const fake = JSON.stringify([{ ...pa.rows[0], seq: after + 2 }]);
    await edgeCache().put(
      bogus,
      new Response(fake, { headers: { "cache-control": "public, max-age=60", "x-segv-last-seq": String(after + 2), "x-segv-last-h": pa.rows[0].h } }),
    );
    const c = (await (await api(`/api/log?after=${after + 1}&limit=1`)).json()) as { rows: WireRow[] };
    expect(c.rows[0].seq).toBe(after + 2);
    expect(c.rows[0].tag).not.toBe(pa.rows[0].tag);
    await downloadVerified(1000);

    // The tail page is never cacheable.
    const tail = await api(`/api/log?after=${h2.seq - 1}&limit=5`);
    expect(tail.headers.get("cache-control")).toBe("no-store");
    expect(((await tail.json()) as { rows: unknown[] }).rows).toHaveLength(1);
  });
});

describe("lookups", () => {
  it("users: falls back to the log when the D1 index lags", async () => {
    const a = makeAccount();
    const seq = await registerOk(a);
    await env.DB.prepare("DELETE FROM users WHERE uid = ?1").bind(a.uidB64).run();
    const res = await api(`/api/users/${a.handle}`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ uid: a.uidB64, handle: a.handle, bundle: a.bundle, sig: a.sig, seq });
  });

  it("users: 400 on invalid handles, 404 on unknown ones", async () => {
    expect((await api("/api/users/AB")).status).toBe(400);
    expect((await api("/api/users/has-dash")).status).toBe(400);
    expect((await api("/api/users/%61bc")).status).toBe(400);
    const res = await api("/api/users/nobody_here");
    expect(res.status).toBe(404);
    expectApiHeaders(res);
  });

  it("wraps: empty list for unknown ids, 400 on invalid ids", async () => {
    const res = await api(`/api/wraps/${P.b64u(P.random(32))}`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ wraps: [] });
    expect((await api("/api/wraps/a+b")).status).toBe(400);
    expect((await api(`/api/wraps/${P.b64u(P.random(1024))}`)).status).toBe(400); // > 1023 bytes
    expect((await api(`/api/wraps/${P.b64u(P.random(1023))}`)).status).toBe(200);
    expect((await api(`/api/wraps/${P.b64u(P.random(32))}?uid=xyz`)).status).toBe(400);
    expect((await api("/api/wraps/AB", { method: "POST" })).status).toBe(405);
  });
});

describe("blobs", () => {
  const putBlob = async (id: string, blob: BodyInit | Uint8Array | null, headers: Record<string, string> = {}, ip?: string) =>
    api(`/api/blob/${id}`, { method: "PUT", body: blob, headers: { "content-type": "application/octet-stream", ...headers }, ip });

  it("PUT then GET; idempotent re-upload", async () => {
    const { blob, id, key } = P.encryptBlob(P.utf8("pretend this is a webp"));
    const pow = await powHeader("blob", P.fromB64u(id), { bytes: blob.length });
    const res = await putBlob(id, blob, { "x-segv-pow": pow });
    expect(res.status, await res.clone().text()).toBe(201);
    expect(await res.json()).toEqual({ id, size: blob.length });
    expect((await putBlob(id, blob, { "x-segv-pow": pow })).status).toBe(201);

    const get = await api(`/api/blob/${id}`);
    expect(get.status).toBe(200);
    expect(get.headers.get("content-type")).toBe("application/octet-stream");
    expect(get.headers.get("cache-control")).toBe("public, max-age=31536000, immutable");
    expect(get.headers.get("x-content-type-options")).toBe("nosniff");
    const etag = get.headers.get("etag");
    expect(etag).toBeTruthy();
    const got = new Uint8Array(await get.arrayBuffer());
    expect(P.utf8("pretend this is a webp")).toEqual(P.decryptBlob(got, id, key));

    const cached = await api(`/api/blob/${id}`, { headers: { "if-none-match": etag! } });
    expect(cached.status).toBe(304);
    expect((await api(`/api/blob/${id}`, { headers: { "if-none-match": '"other"' } })).status).toBe(200);
    expect((await api(`/api/blob/${id}`, { headers: { "if-match": '"other"' } })).status).toBe(200);
  });

  it("400 when the id does not match the content", async () => {
    const { blob } = P.encryptBlob(P.utf8("a"));
    const wrongId = P.b64u(P.H(P.utf8("something else")));
    const res = await putBlob(wrongId, blob, { "x-segv-pow": await powHeader("blob", P.fromB64u(wrongId), { bytes: blob.length }) });
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toMatch(/does not match/);
    expect((await api(`/api/blob/${wrongId}`)).status).toBe(404);
    expect(await env.BLOBS.head(`b/${wrongId}`)).toBeNull();
  });

  it("streams large bodies into R2: a mismatching 3 MiB body is rejected and nothing is stored", async () => {
    const good = bigRandom(3 * 1024 * 1024);
    const id = P.b64u(P.H(good));
    const bad = good.slice();
    bad[bad.length - 1] ^= 1; // differs only in the last byte: the mismatch shows only at the end
    const pow = await powHeader("blob", P.fromB64u(id), { bytes: bad.length });
    const res = await putBlob(id, bad, { "x-segv-pow": pow });
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toMatch(/does not match/);
    expect(await env.BLOBS.head(`b/${id}`)).toBeNull();
    expect((await api(`/api/blob/${id}`)).status).toBe(404);
    expect(await env.DB.prepare("SELECT 1 FROM blobs WHERE id = ?1").bind(id).first()).toBeNull();
    // The right body with the same PoW goes through.
    const ok = await putBlob(id, good, { "x-segv-pow": pow });
    expect(ok.status, await ok.clone().text()).toBe(201);
    const obj = await env.BLOBS.head(`b/${id}`);
    expect(obj?.size).toBe(good.length);
    // The registry keeps the day only.
    const row = await env.DB.prepare("SELECT size, created_at FROM blobs WHERE id = ?1").bind(id).first<{ size: number; created_at: number }>();
    expect(row?.size).toBe(good.length);
    expect(row!.created_at % 86_400_000).toBe(0);
  });

  it("blob proof of work is priced by Content-Length above 1 MiB", async () => {
    const data = bigRandom(3 * 1024 * 1024 + 5);
    const id = P.b64u(P.H(data));
    const required = need("blob", data.length);
    expect(required).toBe(DIFF.blob + 2);
    const w = currentWindow();
    const cheap = await putBlob(id, data, { "x-segv-pow": `${w}.${nonceBetween("blob", w, P.fromB64u(id), DIFF.blob, required)}` });
    expect(cheap.status).toBe(403);
    expect(await errorOf(cheap)).toMatch(/insufficient/);
    expect(need("blob", 1024 * 1024)).toBe(DIFF.blob);
  });

  it("411 without Content-Length, 413 above BLOB_MAX, 400 on bad ids", async () => {
    const { blob, id } = P.encryptBlob(P.utf8("b"));
    const pow = await powHeader("blob", P.fromB64u(id), { bytes: blob.length });
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(blob);
        c.close();
      },
    });
    const noLen = await putBlob(id, stream, { "x-segv-pow": pow });
    expect(noLen.status).toBe(411);

    const huge = new Uint8Array(P.BLOB_MAX + 1);
    const hugeId = P.b64u(P.H(huge));
    const tooBig = await putBlob(hugeId, huge, { "x-segv-pow": await powHeader("blob", P.fromB64u(hugeId)) });
    expect(tooBig.status).toBe(413);

    expect((await putBlob("short", blob)).status).toBe(400);
    expect((await api(`/api/blob/${"A".repeat(42)}B`)).status).toBe(400); // non-canonical 43 chars
    expect((await api(`/api/blob/${P.b64u(P.random(32))}`)).status).toBe(404);
    expect((await api(`/api/blob/${id}`, { method: "POST" })).status).toBe(405);
  });
});

describe("proof of work", () => {
  const body = () => jsonBytes({ rows: wireRows([randomMsgRow()]) });
  const send = (bytes: Uint8Array, pow?: string) =>
    api("/api/append", { method: "POST", body: bytes, headers: pow === undefined ? {} : { "x-segv-pow": pow } });

  it("403 when missing, malformed, stale, future, insufficient, wrong scope or wrong body", async () => {
    const bytes = body();
    const digest = P.H(bytes);
    const w = currentWindow();
    const h0 = await head();

    const cases: [string, string | undefined, RegExp][] = [
      ["missing", undefined, /missing/],
      ["malformed", "abc", /malformed/],
      ["no nonce", `${w}.`, /malformed/],
      ["negative", `${w}.-1`, /malformed/],
      ["stale", await powHeader("append", digest, { window: w - 2 }), /stale/],
      ["future", await powHeader("append", digest, { window: w + 1 }), /stale/],
      ["insufficient", `${w}.${badNonce("append", w, digest)}`, /insufficient/],
    ];
    // A nonce valid for another scope / another body but not for this one.
    let n = 0;
    while (!P.powCheck(P.powPre("register", w, digest), n, DIFF.append) || P.powCheck(P.powPre("append", w, digest), n, DIFF.append)) n++;
    cases.push(["wrong scope", `${w}.${n}`, /insufficient/]);
    const other = P.H(body());
    n = 0;
    while (!P.powCheck(P.powPre("append", w, other), n, DIFF.append) || P.powCheck(P.powPre("append", w, digest), n, DIFF.append)) n++;
    cases.push(["wrong body", `${w}.${n}`, /insufficient/]);

    for (const [name, pow, msg] of cases) {
      const res = await send(bytes, pow);
      expect(res.status, name).toBe(403);
      expect(await errorOf(res), name).toMatch(msg);
    }
    expect(await head()).toEqual(h0);
  });

  it("accepts the previous window", async () => {
    const bytes = body();
    const res = await send(bytes, await powHeader("append", P.H(bytes), { window: currentWindow() - 1, bytes: bytes.length }));
    expect(res.status).toBe(200);
  });

  it("blob PoW is over the raw 32-byte id", async () => {
    const { blob, id } = P.encryptBlob(P.utf8("c"));
    const w = currentWindow();
    const bad = await api(`/api/blob/${id}`, {
      method: "PUT",
      body: blob,
      headers: { "x-segv-pow": `${w}.${badNonce("blob", w, P.fromB64u(id))}` },
    });
    expect(bad.status).toBe(403);
    // A PoW over H(body) instead of the id is rejected too (unless it happens to satisfy both).
    let n = 0;
    while (P.powCheck(P.powPre("blob", w, P.fromB64u(id)), n, DIFF.blob) || !P.powCheck(P.powPre("blob", w, P.H(P.utf8(id))), n, DIFF.blob)) n++;
    const wrong = await api(`/api/blob/${id}`, { method: "PUT", body: blob, headers: { "x-segv-pow": `${w}.${n}` } });
    expect(wrong.status).toBe(403);
  });
});

describe("rate limiting", () => {
  it("429 once an IP exceeds the blob budget (20/min); other IPs are unaffected", async () => {
    const ip = freshIp();
    const id = P.b64u(P.random(32));
    const statuses: number[] = [];
    for (let i = 0; i < 21; i++) {
      const res = await api(`/api/blob/${id}`, { method: "PUT", body: new Uint8Array(64), ip });
      statuses.push(res.status);
    }
    expect(statuses.slice(0, 20).every((s) => s === 403)).toBe(true); // no PoW
    expect(statuses[20]).toBe(429);
    const other = await api(`/api/blob/${id}`, { method: "PUT", body: new Uint8Array(64) });
    expect(other.status).toBe(403);
  });

  it("IPv6 clients share a budget per /64", async () => {
    const id = P.b64u(P.random(32));
    const prefix = `2001:db8:${((Math.random() * 0xffff) | 0).toString(16)}:1`;
    const statuses: number[] = [];
    for (let i = 0; i < 21; i++) {
      const res = await api(`/api/blob/${id}`, { method: "PUT", body: new Uint8Array(64), ip: `${prefix}::${(i + 1).toString(16)}` });
      statuses.push(res.status);
    }
    expect(statuses[20]).toBe(429);
  });
});

/** Opens /api/ws through the Worker and records frames + the close event. */
async function openWs(opts: { ip?: string; origin?: string | null } = {}) {
  const headers: Record<string, string> = { upgrade: "websocket" };
  if (opts.origin !== null) headers.origin = opts.origin ?? ORIGIN;
  const res = await api("/api/ws", { headers, ip: opts.ip });
  return res;
}

function watch(ws: WebSocket) {
  const frames: string[] = [];
  let closeEv: { code: number; reason: string } | null = null;
  let wake: () => void = () => {};
  ws.addEventListener("message", (e) => {
    frames.push(String(e.data));
    wake();
  });
  ws.addEventListener("close", (e) => {
    closeEv = { code: e.code, reason: e.reason };
    wake();
  });
  const until = (pred: () => boolean, what = "condition") =>
    new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`timeout waiting for ${what}; frames=${frames.length}`)), 5000);
      wake = () => {
        if (pred()) {
          clearTimeout(t);
          resolve();
        }
      };
      wake();
    });
  return { frames, closed: () => closeEv, until };
}

describe("GET /api/ws", () => {
  it("426 without an upgrade", async () => {
    const res = await api("/api/ws");
    expect(res.status).toBe(426);
  });

  it("broadcasts every appended row to connected sockets; ping -> pong", async () => {
    const res = await openWs();
    expect(res.status).toBe(101);
    const ws = res.webSocket!;
    ws.accept();
    const w = watch(ws);

    ws.send("ping");
    await w.until(() => w.frames.includes("pong"), "pong");

    const rows = [randomMsgRow(), randomInvRow()];
    const seqs = await appendOk(rows);
    const tag0 = P.b64u(rows[0].tag);
    await w.until(() => w.frames.some((f) => f.includes(tag0)), "rows frame");
    const msg = JSON.parse(w.frames.find((f) => f.includes(tag0))!) as { type: string; rows: WireRow[] };
    expect(msg.type).toBe("rows");
    expect(msg.rows.map((r) => r.seq)).toEqual(seqs);
    expect(msg.rows.map((r) => r.tag)).toEqual(rows.map((r) => P.b64u(r.tag)));
    expect(msg.rows.map((r) => r.body)).toEqual(rows.map((r) => P.b64u(r.body)));
    // Same rows, same hashes as GET /api/log.
    const page = await getLog(seqs[0] - 1, 2);
    expect(page.rows).toEqual(msg.rows);
    ws.close(1000, "done");
  });

  it("checks Origin: same host or none (non-browser clients) only", async () => {
    for (const origin of ["https://evil.example", "null", "https://segv.test.evil.example", "http://segv.test:8080", "garbage"]) {
      const res = await openWs({ origin });
      expect(res.status, origin).toBe(403);
      expect(await errorOf(res)).toMatch(/cross-origin/);
    }
    for (const origin of [ORIGIN, "http://segv.test", null]) {
      const res = await openWs({ origin });
      expect(res.status, String(origin)).toBe(101);
      res.webSocket!.accept();
      res.webSocket!.close(1000);
    }
  });

  it("caps sockets per client (opaque tag, IPv6 by /64) and globally", async () => {
    const ip = freshIp();
    const open: WebSocket[] = [];
    for (let i = 0; i < 8; i++) {
      const res = await openWs({ ip });
      expect(res.status, `socket ${i}`).toBe(101);
      res.webSocket!.accept();
      open.push(res.webSocket!);
    }
    const ninth = await openWs({ ip });
    expect(ninth.status).toBe(429);
    expect(ninth.headers.get("retry-after")).toBe("60");
    const other = await openWs();
    expect(other.status).toBe(101);
    other.webSocket!.accept();
    open.push(other.webSocket!);

    // Global cap: lower it to what is open now (instance field), the next socket is refused.
    await runInDurableObject(stub(), async (inst: LogDO, state) => {
      (inst as unknown as { wsLimits: { total: number } }).wsLimits.total = state.getWebSockets().filter((w) => w.readyState === WebSocket.OPEN).length;
    });
    try {
      const full = await openWs();
      expect(full.status).toBe(503);
    } finally {
      await runInDurableObject(stub(), async (inst: LogDO) => {
        (inst as unknown as { wsLimits: { total: number } }).wsLimits.total = 20_000;
      });
    }
    // Closing frees the client's slots.
    for (const ws of open) ws.close(1000);
    let again = 0;
    for (let i = 0; i < 50 && again !== 101; i++) {
      const res = await openWs({ ip });
      again = res.status;
      if (again === 101) {
        res.webSocket!.accept();
        res.webSocket!.close(1000);
      } else await new Promise((r) => setTimeout(r, 20));
    }
    expect(again).toBe(101);
  });

  it("closes a socket that sends anything but ping", async () => {
    const res = await openWs();
    const ws = res.webSocket!;
    ws.accept();
    const w = watch(ws);
    ws.send("hello");
    await w.until(() => w.closed() !== null, "close");
    expect(w.closed()!.code).toBe(1008);
  });

  it("closes sockets older than the maximum age on the next broadcast", async () => {
    const res = await openWs();
    const ws = res.webSocket!;
    ws.accept();
    const w = watch(ws);
    // Age every open socket by rewriting its accept time.
    await runInDurableObject(stub(), async (_inst: LogDO, state) => {
      for (const s of state.getWebSockets()) s.serializeAttachment({ t: Date.now() - 2 * 60 * 60_000 });
    });
    const row = randomMsgRow();
    await appendOk([row]);
    await w.until(() => w.closed() !== null, "close");
    expect(w.closed()!.code).toBe(4000);
    expect(w.frames.some((f) => f.includes(P.b64u(row.tag)))).toBe(false);
    // A fresh socket gets the next broadcast.
    const fresh = await openWs();
    const fw = fresh.webSocket!;
    fw.accept();
    const ww = watch(fw);
    const row2 = randomMsgRow();
    await appendOk([row2]);
    await ww.until(() => ww.frames.some((f) => f.includes(P.b64u(row2.tag))), "broadcast");
    fw.close(1000);
  });
});

describe("hosts and HSTS", () => {
  it("other hosts: 421 for /api, 308 to the canonical https host for pages", async () => {
    const res = await api("/api/params", { origin: "https://segv-sh.someone.workers.dev" });
    expect(res.status).toBe(421);
    expect(await errorOf(res)).toMatch(/segv\.test/);
    const page = await api("/some/page?x=1", { origin: "https://segv-sh.someone.workers.dev", redirect: "manual" });
    expect(page.status).toBe(308);
    expect(page.headers.get("location")).toBe("https://segv.test/some/page?x=1");
    // Listed hosts are served (localhost = dev / e2e).
    expect((await api("/api/params", { origin: "http://localhost:8787" })).status).toBe(200);
  });

  it("HSTS only over https", async () => {
    const https = await api("/api/params");
    expect(https.headers.get("strict-transport-security")).toBe(HSTS);
    const err = await api("/api/nope");
    expect(err.headers.get("strict-transport-security")).toBe(HSTS);
    const http = await api("/api/params", { origin: "http://localhost:8787" });
    expect(http.headers.get("strict-transport-security")).toBeNull();
  });
});
