import { describe, expect, it } from "vite-plus/test";
import { refKeyOf, refOf } from "~/client/conv";
import * as P from "~/lib/proto";
import { hashOfRef, refOfHash } from "./route";

describe("chat refs in the URL", () => {
  const ak1 = new Uint8Array(32).fill(1);
  const ak2 = new Uint8Array(32).fill(2);
  const conv = P.b64u(new Uint8Array(16).fill(7));

  it("a ref is 12 b64u characters that round-trip through the fragment", () => {
    const ref = refOf(refKeyOf(ak1), conv);
    expect(ref).toMatch(/^[A-Za-z0-9_-]{12}$/);
    expect(refOfHash(hashOfRef(ref))).toBe(ref);
  });

  it("is the same for one account and differs across accounts and copies", () => {
    expect(refOf(refKeyOf(ak1), conv)).toBe(refOf(refKeyOf(ak1), conv));
    expect(refOf(refKeyOf(ak2), conv)).not.toBe(refOf(refKeyOf(ak1), conv));
    expect(refOf(refKeyOf(ak1), `${conv}~1`)).not.toBe(refOf(refKeyOf(ak1), conv));
  });

  it("does not contain the copy key", () => {
    expect(conv).not.toContain(refOf(refKeyOf(ak1), conv));
  });

  it("reads only #c/<12 characters>", () => {
    expect(refOfHash("#c/AbCdEf012_-x")).toBe("AbCdEf012_-x");
    for (const h of [
      "",
      "#",
      "#c/",
      "#c/short",
      "#c/AbCdEf012_-x/",
      "#c/AbCdEf012_-xy",
      "#x/AbCdEf012_-x",
      "c/AbCdEf012_-x",
      "#c/AbCdEf012+/x",
    ])
      expect(refOfHash(h)).toBe("");
  });
});
