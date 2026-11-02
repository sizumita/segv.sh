// Files (docs/PROTOCOL.md §8.3): a file sent as it is, which the other member fetches only when asked, its safe name,
// its size checked against what the blob holds, the limits, and reactions to a file.
import { resolveObjectURL } from "node:buffer";
import { describe, expect, it } from "vite-plus/test";
import {
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
} from "./harness";
import type { Engine, FileRef } from "../src/types";

freshWorldPerTest();

async function urlBytes(url: string): Promise<{ bytes: Uint8Array; type: string }> {
  const b = resolveObjectURL(url);
  if (!b) throw new Error("object URL not found");
  return { bytes: new Uint8Array(await b.arrayBuffer()), type: b.type };
}

const blobGets = (idB?: string) =>
  server().requests.filter(
    (r) => r.method === "GET" && r.path.startsWith(`/api/v2/blob/${idB ?? ""}`),
  ).length;
const blobPuts = () =>
  server().requests.filter((r) => r.method === "PUT" && r.path.startsWith("/api/v2/blob/")).length;

const fileOf = (e: Engine, id: string): FileRef =>
  mustView(e, id).messages.find((m) => m.kind === "file")!.file!;

async function pair() {
  const [alice, bob] = ["alice", "bob"].map((h) => makeUser(h));
  const A = await engineFor(alice);
  const B = await engineFor(bob);
  const id = await A.createConversation(["bob"]);
  await settle(A, B);
  return { alice, bob, A, B, id };
}

describe("files", () => {
  it("sends a file as it is, which the other member fetches only when asked, as application/octet-stream", async () => {
    const { A, B, id } = await pair();
    const secret = P.utf8("%PDF-1.7 private document bytes, metadata included");
    const unread = mustView(B, id).unread;
    await A.sendFile(id, new File([secret as BlobPart], "plan.pdf", { type: "application/pdf" }));
    await settle(A, B);
    expect(A.getState().error).toBe("");
    expect(chat(A, id)).toEqual(["alice: [file plan.pdf]"]);
    expect(chat(B, id)).toEqual(["alice: [file plan.pdf]"]);
    const f = fileOf(B, id);
    expect(f).toMatchObject({ name: "plan.pdf", size: secret.length });
    expect(mustView(B, id).unread).toBe(unread + 1); // a message, like a text
    // Shown, but not fetched: only the user's ask fetches it.
    expect(blobGets(f.id)).toBe(0);
    const got = await urlBytes(await B.loadFile(f));
    expect(blobGets(f.id)).toBe(1);
    expect(P.equalBytes(got.bytes, secret)).toBe(true);
    expect(got.type).toBe("application/octet-stream");
    // cached by id.k: a second ask makes no request
    await B.loadFile(f);
    expect(blobGets(f.id)).toBe(1);
    // the sender has the bytes already
    expect(P.equalBytes((await urlBytes(await A.loadFile(fileOf(A, id)))).bytes, secret)).toBe(
      true,
    );
    expect(blobGets(f.id)).toBe(1);
    // The server only ever stored ciphertext, padded as §8.3 says.
    const stored = server().blobs.bytes(f.id)!;
    expect(stored.length).toBe(P.fileBlobLen(secret.length));
    expect(Buffer.from(stored).includes(Buffer.from(secret))).toBe(false);
  });

  it("an empty file is a file too", async () => {
    const { A, B, id } = await pair();
    await A.sendFile(id, new File([], "empty.txt"));
    await settle(A, B);
    const f = fileOf(B, id);
    expect(f).toMatchObject({ name: "empty.txt", size: 0 });
    expect((await urlBytes(await B.loadFile(f))).bytes.length).toBe(0);
  });

  it("sends the safe name, and shows the safe name of an unsafe name that another client sent", async () => {
    const { alice, A, B, id } = await pair();
    await A.sendFile(id, new File([P.utf8("x") as BlobPart], " invoice‮fdp.exe "));
    await settle(A, B);
    expect(fileOf(B, id).name).toBe("invoice_fdp.exe");
    // A row whose name is not safe, built without the engine.
    const ep = epoch(A, id);
    const at = ep.lanes[ep.myIndex].next;
    const { blob, id: blobId, key } = P.encryptBlob(P.utf8("y"));
    server().putBlob(blob);
    const file = { id: P.fromB64u(blobId), k: key, size: 1, name: "../../⁧evil⁩\u0000.sh" };
    postRow(ep, buildMessage(alice, ep, at, { type: P.MT.FILE, file }));
    await settle(A, B);
    const names = mustView(B, id)
      .messages.filter((m) => m.kind === "file")
      .map((m) => m.file!.name);
    expect(names).toEqual(["invoice_fdp.exe", ".._..__evil__.sh"]);
  });

  it("checks the size against the blob, and refuses a blob that would be too large without a request", async () => {
    const { A, B, id } = await pair();
    await A.sendFile(id, new File([P.utf8("twelve bytes") as BlobPart], "a.txt"));
    await settle(A, B);
    const f = fileOf(B, id);
    await expect(B.loadFile({ ...f, size: f.size + 1 })).rejects.toThrow(/does not match/);
    expect(P.equalBytes((await urlBytes(await B.loadFile(f))).bytes, P.utf8("twelve bytes"))).toBe(
      true,
    );
    const n = blobGets();
    await expect(B.loadFile({ ...f, size: 12 * 1024 * 1024 })).rejects.toThrow(/too large/);
    expect(blobGets()).toBe(n);
    await expect(B.loadFile({ ...f, k: P.b64u(P.random(32)) })).rejects.toThrow();
    await expect(B.loadFile({ ...f, id: "../../api/v2/params" })).rejects.toThrow(
      /bad file reference/,
    );
    await expect(B.loadFile({ ...f, size: -1 })).rejects.toThrow(/bad file size/);
  });

  it("refuses a file over FILE_MAX before reading or uploading it", async () => {
    const { A, id } = await pair();
    const puts = blobPuts();
    await A.sendFile(id, new File([new Uint8Array(P.FILE_MAX + 1) as BlobPart], "big.bin"));
    await settle(A);
    expect(A.getState().error).toBe("the file is too large");
    expect(chat(A, id)).toEqual(["alice: [file big.bin] (failed)"]);
    expect(blobPuts()).toBe(puts);
  });

  it("takes reactions like a text or an image", async () => {
    const { A, B, id } = await pair();
    await B.accept(id);
    await A.sendFile(id, new File([P.utf8("z") as BlobPart], "z.txt"));
    await settle(A, B);
    const key = mustView(B, id).messages.find((m) => m.kind === "file")!.key;
    await B.react(id, key, "👍", true);
    await settle(A, B);
    const reactions = mustView(A, id).messages.find((m) => m.kind === "file")!.reactions;
    expect(reactions).toEqual([{ emoji: "👍", count: 1, mine: false }]);
  });
});
