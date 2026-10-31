// Images (docs/PROTOCOL.md §8.1): an encrypted image that the
// other member loads, the cache keyed by id AND key (web-4), and uploads in flight across a logout (engine-11). The
// canvas re-encoder (packages/engine/src/image.ts) needs a DOM, so it is replaced by a pass-through.
import { resolveObjectURL } from "node:buffer";
import { describe, expect, it, vi } from "vite-plus/test";
import {
  I,
  P,
  buildMessage,
  chat,
  engineFor,
  epoch,
  freshWorldPerTest,
  makeUser,
  mustView,
  postRow,
  server,
  settle,
  sleep,
} from "./harness";

vi.mock("../src/image", () => ({
  prepareImage: async (file: Blob) => ({
    bytes: new Uint8Array(await file.arrayBuffer()),
    mime: "image/webp" as const,
    w: 4,
    h: 3,
  }),
}));

freshWorldPerTest();

async function urlBytes(url: string): Promise<Uint8Array> {
  const b = resolveObjectURL(url);
  if (!b) throw new Error("object URL not found");
  return new Uint8Array(await b.arrayBuffer());
}

const blobGets = () => server().requests.filter((r) => r.path.startsWith("/api/v2/blob/") && r.method === "GET").length;

describe("images", () => {
  it("sends an encrypted image that the other member can load", async () => {
    const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await A.createConversation(["bob"]);
    await settle(A, B);
    const secret = P.utf8("RIFF....WEBPVP8 private photo bytes");
    await A.sendImage(id, new File([secret as BlobPart], "p.webp", { type: "image/webp" }));
    await settle(A, B);
    expect(A.getState().error).toBe("");
    expect(chat(B, id)).toEqual(["alice: [image]"]);
    const img = mustView(B, id).messages.find((m) => m.kind === "image")!.image!;
    expect(server().blobs.has(img.id)).toBe(true);
    expect(P.equalBytes(await urlBytes(await B.loadImage(img)), secret)).toBe(true);
    // The server only ever stored ciphertext.
    const stored = server().blobs.bytes(img.id)!;
    expect(Buffer.from(stored).includes(Buffer.from(secret))).toBe(false);
  });

  it("web-4: a message naming another conversation's blob with a wrong key does not get the cached plaintext", async () => {
    const [alice, bob, mallory] = ["alice", "bob", "mallory"].map((h) => makeUser(h));
    const A = await engineFor(alice);
    const B = await engineFor(bob);
    const M = await engineFor(mallory);
    const private1 = await A.createConversation(["bob"]);
    const stranger = await M.createConversation(["alice"]);
    await settle(A, B, M);
    const secret = P.utf8("alice private photo");
    await A.sendImage(private1, new File([secret as BlobPart], "p.webp", { type: "image/webp" }));
    await settle(A, B, M);
    const real = mustView(A, private1).messages.find((m) => m.kind === "image")!.image!;
    // Alice's session has the plaintext cached (she sent it): no download.
    const before = blobGets();
    expect(P.equalBytes(await urlBytes(await A.loadImage(real)), secret)).toBe(true);
    expect(blobGets()).toBe(before);
    // Mallory (who learned the blob id, e.g. as the operator) sends alice an image row naming it with her own key.
    const ep = epoch(M, stranger);
    const at = ep.lanes[ep.myIndex].next;
    const image = { id: P.fromB64u(real.id), k: P.random(32), mime: 1 as const, w: 4, h: 3 };
    postRow(ep, buildMessage(mallory, ep, at, { type: P.MT.IMAGE, image }));
    await settle(A);
    const shown = mustView(A, stranger).messages.find((m) => m.kind === "image")!;
    expect(shown.fromHandle).toBe("mallory");
    await expect(A.loadImage(shown.image!)).rejects.toThrow();
    await expect(A.loadImage({ ...real, id: "../../api/v2/params" })).rejects.toThrow(/bad image reference/);
  });

  it("engine-11: an image upload in flight across a logout does not touch the next account", async () => {
    const [alice, bob, dave] = ["alice", "bob", "dave"].map((h) => makeUser(h));
    const E = await engineFor(alice);
    const id = await E.createConversation(["bob"]);
    await settle(E);
    let release!: () => void;
    // holds the image's upload only (a snapshot's blob of the next session goes through)
    server().hooks.beforeRequest = (m, p) => {
      if (m === "PUT" && p.startsWith("/api/v2/blob/") && !release)
        return new Promise<void>((r) => (release = r));
    };
    const p = E.sendImage(id, new File([P.utf8("alice only") as BlobPart], "a.webp", { type: "image/webp" }));
    await sleep(50);
    expect(release).toBeTypeOf("function");
    await E.logout();
    await I(E).unlock(dave.AK, dave.uid, "dave");
    await settle(E);
    server().hooks.beforeRequest = undefined;
    release();
    await p;
    await settle(E);
    expect(E.getState().me?.handle).toBe("dave");
    expect(E.getState().error).toBe(""); // alice's failure is not reported in dave's session
    expect(I(E).imageCache.size).toBe(0); // alice's plaintext is not cached in dave's session
    void bob;
  });

  it("engine-11: an image alice picked is never posted as the next account in a conversation they share", async () => {
    const [alice, bob, dave] = ["alice", "bob", "dave"].map((h) => makeUser(h));
    const E = await engineFor(alice);
    const B = await engineFor(bob);
    const id = await E.createConversation(["bob", "dave"]); // dave is a member too
    await settle(E, B);
    let release!: () => void;
    // holds the image's upload only (a snapshot's blob of the next session goes through)
    server().hooks.beforeRequest = (m, p) => {
      if (m === "PUT" && p.startsWith("/api/v2/blob/") && !release)
        return new Promise<void>((r) => (release = r));
    };
    const p = E.sendImage(id, new File([P.utf8("picked by alice") as BlobPart], "a.webp", { type: "image/webp" }));
    await sleep(50);
    await E.logout();
    await I(E).unlock(dave.AK, dave.uid, "dave"); // same tab, another account that is in the same conversation
    await settle(E);
    server().hooks.beforeRequest = undefined;
    release();
    await p;
    await settle(E, B);
    expect(chat(B, id)).not.toContain("dave: [image]");
    expect(chat(B, id)).toEqual([]);
  });
});
