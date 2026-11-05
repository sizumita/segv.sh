// The session's decrypted images (image-cache.ts): one fetch per image while it is cached, an image kept while the UI
// shows it, the least recently used of the others revoked beyond the limits, and nothing kept after a failure.
import { describe, expect, it } from "vite-plus/test";
import { ImageCache } from "./image-cache";

function cache(limits = { idle: 2, idleBytes: 1000 }) {
  const revoked: string[] = [];
  const made: string[] = [];
  const c = new ImageCache(limits, (u) => revoked.push(u));
  const make =
    (key: string, size = 100) =>
    () => {
      made.push(key);
      return Promise.resolve({ url: `blob:${key}`, size });
    };
  return { c, revoked, made, make };
}

const tick = () => new Promise((r) => setTimeout(r, 0));

describe("ImageCache", () => {
  it("makes an image once while it is cached", async () => {
    const { c, made, make } = cache();
    expect(await c.hold("a", make("a"))).toBe("blob:a");
    expect(await c.hold("a", make("a"))).toBe("blob:a");
    expect(made).toEqual(["a"]);
  });

  it("keeps an image that is held, whatever the limits", async () => {
    const { c, revoked, make } = cache({ idle: 0, idleBytes: 0 });
    await c.hold("a", make("a"));
    await tick();
    expect(revoked).toEqual([]);
    c.release("a");
    await tick();
    expect(revoked).toEqual(["blob:a"]);
    expect(c.size).toBe(0);
  });

  it("keeps an image until its last holder releases it", async () => {
    const { c, revoked, make } = cache({ idle: 0, idleBytes: 0 });
    await c.hold("a", make("a"));
    await c.hold("a", make("a"));
    c.release("a");
    await tick();
    expect(revoked).toEqual([]);
    c.release("a");
    c.release("a"); // one release too many does nothing
    await tick();
    expect(revoked).toEqual(["blob:a"]);
  });

  it("revokes the least recently used idle images beyond the count", async () => {
    const { c, revoked, made, make } = cache({ idle: 2, idleBytes: 1e9 });
    for (const k of ["a", "b", "c"]) {
      await c.hold(k, make(k));
      await tick();
    }
    // a used again: b is now the least recently used
    await c.hold("a", make("a"));
    for (const k of ["a", "b", "c", "a"]) c.release(k);
    await tick();
    expect(revoked).toEqual(["blob:b"]);
    expect(await c.hold("a", make("a"))).toBe("blob:a");
    expect(made).toEqual(["a", "b", "c"]);
  });

  it("revokes idle images beyond the bytes", async () => {
    const { c, revoked, make } = cache({ idle: 10, idleBytes: 250 });
    for (const k of ["a", "b", "c"]) {
      await c.hold(k, make(k, 100));
      c.release(k);
      await tick();
    }
    expect(revoked).toEqual(["blob:a"]);
  });

  it("keeps a sent image idle, and evicts it like any other", async () => {
    const { c, revoked, made, make } = cache({ idle: 1, idleBytes: 1e9 });
    c.put("s", "blob:s", 10);
    expect(await c.hold("s", make("s"))).toBe("blob:s");
    expect(made).toEqual([]);
    c.release("s");
    await c.hold("x", make("x"));
    c.release("x");
    await tick();
    expect(revoked).toEqual(["blob:s"]);
  });

  it("keeps nothing after a failure", async () => {
    const { c, made } = cache();
    await expect(c.hold("a", () => Promise.reject(new Error("not found")))).rejects.toThrow();
    await tick();
    expect(c.size).toBe(0);
    await c.hold("a", () => {
      made.push("again");
      return Promise.resolve({ url: "blob:a", size: 1 });
    });
    expect(made).toEqual(["again"]);
  });

  it("revokes everything when cleared, also an image still being made", async () => {
    const { c, revoked, make } = cache();
    await c.hold("a", make("a"));
    let finish!: (v: { url: string; size: number }) => void;
    const pending = c.hold("b", () => new Promise((r) => (finish = r)));
    c.clear();
    await tick();
    expect(revoked).toEqual(["blob:a"]);
    finish({ url: "blob:b", size: 1 });
    await pending;
    await tick();
    expect(revoked).toEqual(["blob:a", "blob:b"]);
    expect(c.size).toBe(0);
  });

  it("drops one image whatever holds it, also one still being made, and leaves the others", async () => {
    const { c, revoked, made, make } = cache();
    await c.hold("a", make("a"));
    c.put("s", "blob:s", 10);
    await c.hold("k", make("k"));
    c.drop("a"); // held: revoked all the same
    c.drop("s"); // idle
    c.drop("none"); // nothing cached: nothing to do
    await tick();
    expect(revoked).toEqual(["blob:a", "blob:s"]);
    expect(c.size).toBe(1);
    c.release("a"); // its holder lets go later: nothing more happens
    await tick();
    expect(revoked).toEqual(["blob:a", "blob:s"]);
    // one being made is revoked once it is made, and the next hold makes it again
    let finish!: (v: { url: string; size: number }) => void;
    const pending = c.hold("b", () => new Promise((r) => (finish = r)));
    c.drop("b");
    finish({ url: "blob:b", size: 1 });
    await pending;
    await tick();
    expect(revoked).toEqual(["blob:a", "blob:s", "blob:b"]);
    expect(await c.hold("b", make("b"))).toBe("blob:b");
    expect(made).toEqual(["a", "k", "b"]);
    expect(await c.hold("k", make("k"))).toBe("blob:k");
  });
});
