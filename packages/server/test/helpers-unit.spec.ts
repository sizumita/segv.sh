/** Pure helpers, exercised inside workerd (where the native base64 path is active). */
import { describe, expect, it } from "vitest";
import * as P from "@segv/protocol/proto";
import { clientKey, clientTag } from "../src/abuse";
import { inboxCacheControl } from "../src/api";
import { parseShardMap, shardBitsOf, shardsOf } from "../src/env";
import { dec64, enc64 } from "../src/b64";
import { logErr } from "../src/http";
import { appHosts } from "../src/hosts";
import {
  decodeBatches,
  decodeIdxEntry,
  dirBytes,
  encodeBatchEntry,
  encodeIdxEntry,
  manifestJson,
  parseManifest,
  sealPage,
} from "../src/seal";

const req = (ip?: string) =>
  new Request("https://x/", { headers: ip === undefined ? {} : { "cf-connecting-ip": ip } });

describe("SHARD_MAP (§9.1)", () => {
  it("parses E:S entries, applies the last entry at or below the era, and rejects malformed maps", () => {
    expect(parseShardMap(undefined)).toEqual([]);
    expect(parseShardMap(null)).toEqual([]);
    expect(parseShardMap("")).toEqual([]);
    expect(parseShardMap(" 42:1, 60:4 ,70:256")).toEqual([
      { from: 42, bits: 0 },
      { from: 60, bits: 2 },
      { from: 70, bits: 8 },
    ]);
    const map = parseShardMap("60:4,70:256")!;
    expect([59, 60, 69, 70, 1000].map((E) => shardsOf(map, E))).toEqual([1, 4, 4, 256, 256]);
    expect(shardBitsOf(map, 65)).toBe(2);
    expect(shardsOf([], 5)).toBe(1);
    expect(parseShardMap("0:65536")).toEqual([{ from: 0, bits: 16 }]);
    for (const bad of [
      "60",
      "60:3",
      "60:0",
      "60:131072",
      "70:2,60:4",
      "60:2,60:4",
      "65535:2",
      "a:2",
      "60:2,",
      42,
    ])
      expect(parseShardMap(bad), String(bad)).toBeNull();
  });
});

describe("inboxCacheControl (§10.5)", () => {
  it("expires with the slot it reports: whole seconds, at least 1, at most Δin", () => {
    const D = 10;
    const closed = 1234;
    const end = P.T0_MS + (closed + 1) * D * 1000;
    expect(inboxCacheControl(closed, end - 7_400, D)).toBe("public, max-age=7");
    expect(inboxCacheControl(closed, end - 300, D)).toBe("public, max-age=1");
    expect(inboxCacheControl(closed, end + 5_000, D)).toBe("public, max-age=1"); // the object's clock behind the Worker's
    expect(inboxCacheControl(closed, end - 25_000, D)).toBe("public, max-age=10"); // the Worker's clock behind the object's
    expect(inboxCacheControl(closed, end - 999, 1)).toBe("public, max-age=1");
    expect(inboxCacheControl(closed, end - 1_000, 1)).toBe("public, max-age=1");
  });
});

describe("b64", () => {
  it("matches proto.b64u / proto.fromB64u for every length", () => {
    for (let n = 0; n < 100; n++) {
      const b = P.random(n);
      const s = P.b64u(b);
      expect(enc64(b)).toBe(s);
      expect(dec64(s)).toEqual(b);
    }
    const big = P.random(20_000);
    expect(enc64(big)).toBe(P.b64u(big));
  });

  it("rejects everything proto rejects", () => {
    for (const s of ["A", "AB==", "AB=", "A B", "AB\n", "+/", "AF", "AAB", "Zm9vé", " Zm9v"]) {
      expect(() => P.fromB64u(s), s).toThrow();
      expect(() => dec64(s), s).toThrow();
    }
    expect(() => dec64(42)).toThrow();
  });
});

describe("clientKey", () => {
  it("keys IPv4 by address and IPv6 by /64", () => {
    expect(clientKey(req("203.0.113.7"))).toBe("4:203.0.113.7");
    expect(clientKey(req("2001:db8:a:b:1:2:3:4"))).toBe("6:2001:db8:a:b::/64");
    expect(clientKey(req("2001:DB8:A:B::99"))).toBe("6:2001:db8:a:b::/64");
    expect(clientKey(req("2001:db8::1"))).toBe("6:2001:db8:0:0::/64");
    expect(clientKey(req("::1"))).toBe("6:0:0:0:0::/64");
    expect(clientKey(req("fe80::1%eth0"))).toBe("6:fe80:0:0:0::/64");
    expect(clientKey(req("2001:0db8:000a:000b::"))).toBe("6:2001:db8:a:b::/64");
    expect(clientKey(req("64:ff9b::192.0.2.1"))).toBe("6:64:ff9b:0:0::/64");
  });

  it("keys IPv4-mapped IPv6 by the IPv4 address", () => {
    expect(clientKey(req("::ffff:198.51.100.9"))).toBe("4:198.51.100.9");
    expect(clientKey(req("::ffff:c633:6409"))).toBe("4:198.51.100.9");
  });

  it("buckets missing / invalid addresses", () => {
    expect(clientKey(req())).toBe("x:unknown");
    expect(clientKey(req("not an ip"))).toBe("x:unknown");
    expect(clientKey(req("1.2.3.256"))).toBe("x:unknown");
    for (const bad of [
      "1:2:3:4:5:6:7:8:9",
      "1::2::3",
      "12345::",
      ":1:2:3:4:5:6:7",
      "1:2:3:4:5:6:7:8::",
      "::1.2.3",
    ]) {
      expect(clientKey(req(bad)), bad).toBe("x:invalid");
    }
  });
});

describe("logErr", () => {
  it("redacts ids and addresses, keeps the message readable", () => {
    const id = P.b64u(P.random(32));
    const msg = logErr(
      new Error(
        `put: The SHA-256 checksum you specified did not match (${P.hex(P.random(32))}) for b/${id} from 203.0.113.7 / 2001:db8::1`,
      ),
    );
    expect(msg).not.toContain(id);
    expect(msg).not.toContain("203.0.113.7");
    expect(msg).not.toContain("2001:db8::1");
    expect(msg).toContain("Error: put: The SHA-256 checksum you specified did not match");
    expect(logErr(new Error("D1_ERROR: SQLITE_CONSTRAINT_PRIMARYKEY"))).toBe(
      "Error: D1_ERROR: SQLITE_CONSTRAINT_PRIMARYKEY",
    );
    expect(logErr("x".repeat(1000)).length).toBeLessThanOrEqual(300);
  });
});

describe("clientTag / appHosts", () => {
  it("tags are opaque, stable per client key and key-dependent", () => {
    const k1 = P.random(32);
    const r = (ip: string) => req(ip);
    expect(clientTag(k1, r("203.0.113.7"))).toMatch(/^[0-9a-f]{32}$/);
    expect(clientTag(k1, r("203.0.113.7"))).toBe(clientTag(k1, r("203.0.113.7")));
    expect(clientTag(k1, r("2001:db8:a:b::1"))).toBe(clientTag(k1, r("2001:db8:a:b::2"))); // same /64
    expect(clientTag(k1, r("203.0.113.7"))).not.toBe(clientTag(k1, r("203.0.113.8")));
    expect(clientTag(k1, r("203.0.113.7"))).not.toBe(clientTag(P.random(32), r("203.0.113.7")));
  });

  it("parses APP_HOSTS", () => {
    expect(appHosts({ APP_HOSTS: " Segv.sh , localhost,," } as unknown as Env)).toEqual([
      "segv.sh",
      "localhost",
    ]);
    expect(appHosts({ APP_HOSTS: "" } as unknown as Env)).toEqual([]);
    expect(appHosts({} as unknown as Env)).toEqual([]);
  });
});

describe('sealed shards (§9.1 "Paging")', () => {
  it("idx and batches entries round-trip, with 48- and 64-bit offsets", () => {
    const label = P.random(16);
    for (const off of [0, 1, 2 ** 32 + 5, 2 ** 48 - 1]) {
      expect(decodeIdxEntry(encodeIdxEntry(label, 7, 3, off), 0)).toEqual({
        label,
        t: 7,
        cls: 3,
        off,
      });
    }
    expect(() => encodeIdxEntry(label, 1, 0, 2 ** 48)).toThrow();
    expect(() => decodeIdxEntry(encodeIdxEntry(label, 1, 4, 0), 0)).toThrow(/malformed/);
    const be = encodeBatchEntry(5, 2, P.random(32), P.random(32), 2 ** 40 + 3);
    expect(be.length).toBe(P.SEAL_BATCH_ENTRY);
    expect(new DataView(be.buffer).getBigUint64(72)).toBe(BigInt(2 ** 40 + 3));
  });

  it("decodeBatches checks the count, the order, the offsets and the final head; sealPage composes by the §10.9 rule", () => {
    const cid = P.shardCid(3, 0);
    const mk = (t: number, n: number, prev: Uint8Array) => {
      const root = P.random(32);
      return { t, n, root, head: P.nextHead(cid, prev, t, n, root) };
    };
    const b1 = mk(10, 1, P.ZERO32);
    const b2 = mk(20, 2, b1.head);
    const len1 = 72 + 1 * (17 + 296);
    const len2 = 72 + 2 * (17 + 296);
    const bytes = P.concat(
      encodeBatchEntry(b1.t, b1.n, b1.root, b1.head, 0),
      encodeBatchEntry(b2.t, b2.n, b2.root, b2.head, len1),
    );
    const m = { nb: 2, head: b2.head, rows: { size: len1 + len2, sha256: [] } };
    const table = decodeBatches(bytes, m);
    expect(table.map((b) => [b.t, b.n, b.off, b.len])).toEqual([
      [10, 1, 0, len1],
      [20, 2, len1, len2],
    ]);
    expect(() => decodeBatches(bytes, { ...m, nb: 1 })).toThrow(/size/);
    expect(() => decodeBatches(bytes, { ...m, head: P.ZERO32 })).toThrow(/head/);
    expect(() => decodeBatches(bytes, { ...m, rows: { size: len1 + 10, sha256: [] } })).toThrow(
      /malformed/,
    );
    expect(sealPage(table, 0, 1 << 20)).toMatchObject({ more: false, from: 0, bytes: len1 + len2 });
    expect(sealPage(table, 0, 1 << 20).batches.map((b) => b.t)).toEqual([10, 20]);
    expect(sealPage(table, 0, len1)).toMatchObject({ more: true, bytes: len1 });
    expect(sealPage(table, 0, 1)).toMatchObject({ more: true, bytes: len1 }); // always at least one batch
    expect(sealPage(table, 10, 1)).toMatchObject({ more: false, from: len1, bytes: len2 });
    expect(sealPage(table, 15, 1 << 20).batches.map((b) => b.t)).toEqual([20]);
    expect(sealPage(table, 20, 1 << 20)).toEqual({ batches: [], more: false, from: 0, bytes: 0 });
  });

  it("the manifest round-trips through JSON and is checked field by field", () => {
    const summary = {
      era: 5,
      shard: 1,
      sbits: 1,
      kroute: P.random(32),
      head: P.random(32),
      tLast: 99,
      part: 5 * 1024 * 1024,
      n: 3,
      b: 1,
      dir: dirBytes(new Uint32Array([0, 2, 3])),
      nb: 1,
      rows: { size: 72 + 3 * (17 + 296), sha256: [P.random(32)] },
      idx: { size: 3 * P.SEAL_IDX_ENTRY, sha256: [P.random(32)] },
      batches: { size: P.SEAL_BATCH_ENTRY, sha256: [P.random(32)] },
    };
    const sig = P.random(64);
    const text = manifestJson(summary, sig);
    const m = parseManifest(text);
    expect(m).toMatchObject({ ...summary, sig });
    expect([...m.bucketDir]).toEqual([0, 2, 3]);
    expect(P.sealSigMsg(m)).toEqual(P.sealSigMsg(summary));
    const bad = (patch: (j: Record<string, unknown>) => void) => {
      const j = JSON.parse(text) as Record<string, unknown>;
      patch(j);
      return () => parseManifest(JSON.stringify(j));
    };
    expect(bad((j) => (j.v = 2))).toThrow(/version/);
    expect(bad((j) => (j.shard = 2))).toThrow(/era \/ shard/);
    expect(bad((j) => ((j.rows as { n: number }).n = 4))).toThrow(/dir total/);
    expect(bad((j) => ((j.idx as { sha256: string[] }).sha256 = []))).toThrow(/parts/);
    expect(
      bad((j) => ((j.idx as { dir: string }).dir = P.b64u(dirBytes(new Uint32Array([0, 3, 2]))))),
    ).toThrow(/dir/);
    expect(bad((j) => ((j.batches as { size: number }).size = 81))).toThrow(/sizes/);
    expect(() => parseManifest("nope")).toThrow(/JSON/);
  });
});
