// S_E > 1 as the fake world runs it (docs/PROTOCOL.md §4.4, §9.1, §9.5, §10.9): rows land in the shard of their
// routing value, the API answers are unchanged, every shard has its own feed and head chain, the checkpoint lists
// every shard, and the engine accepts the parameter.
import { describe, expect, it } from "vite-plus/test";
import * as W from "@segv/protocol/wire";
import { P, chat, engineFor, freshWorldPerTest, makeUser, server, settle } from "./harness";

freshWorldPerTest({ shards: 4 });

describe("four shards per era", () => {
  it("messages flow; rows sit in shard(E, label); each shard's feed verifies and the checkpoint lists all four", async () => {
    const alice = makeUser("alice");
    const bob = makeUser("bob");
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(["@bob"]);
    await settle(A, B);
    for (let k = 0; k < 6; k++) await A.sendText(id, `message ${k}`);
    await settle(A, B);
    expect(chat(B, id)).toEqual(Array.from({ length: 6 }, (_, k) => `alice: message ${k}`));

    const w = server();
    const E = w.era;
    expect(((await (await w.fetch("/api/v2/params")).json()) as { shards: number }).shards).toBe(4);
    expect(((await (await w.fetch(`/api/v2/era/${E}`)).json()) as { shards: number }).shards).toBe(
      4,
    );
    // The rows of this era spread over the shards by v (two users' lanes, the control lane and the self lanes).
    const used = new Set(w.shard.rows(E).map((r) => w.shardOf(E, r.label)));
    expect(used.size).toBeGreaterThanOrEqual(2);
    for (const i of used) expect(i).toBeLessThan(4);

    // Every batch closes, then a checkpoint over all four shards.
    w.tick(60_000);
    expect(w.ckpt.tick()).not.toBeNull();
    const latest = (await (await w.fetch("/api/v2/ckpt/latest")).json()) as {
      heads: { cid: string; head: string }[];
    };
    let rows = 0;
    for (let i = 0; i < 4; i++) {
      let head: Uint8Array = P.ZERO32;
      for (let after = 0; ;) {
        const res = await w.fetch(`/api/v2/feed/${E}/${i}?after=${after}`);
        expect(res.status).toBe(200);
        const page = W.decodeFeed(new Uint8Array(await res.arrayBuffer()));
        for (const b of page.batches) {
          expect(P.mth(b.rows.map((r) => P.leafShard(E, r.label, b.t, r.cls, r.body)))).toEqual(
            b.root,
          );
          head = P.nextHead(P.shardCid(E, i), head, b.t, b.n, b.root);
          expect(b.head).toEqual(head);
          for (const r of b.rows) expect(w.shardOf(E, r.label)).toBe(i);
          rows += b.rows.length;
          after = b.t;
        }
        if (!page.more) break;
      }
      const h = latest.heads.find((x) => x.cid === P.shardCid(E, i));
      expect(h, `shard ${i} in the checkpoint`).toBeDefined();
      expect(h!.head).toBe(P.b64u(head));
    }
    expect(rows).toBe(w.shard.rows(E).length);
    expect(latest.heads.find((x) => x.cid === P.shardCid(E, 4))).toBeUndefined();
    expect((await w.fetch(`/api/v2/feed/${E}/4`)).status).toBe(404);
    expect(A.getState().warnings).toEqual([]);
    expect(B.getState().warnings).toEqual([]);
  });
});
