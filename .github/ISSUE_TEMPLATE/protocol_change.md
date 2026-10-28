---
name: Protocol change
about: Propose a change to what docs/PROTOCOL.md defines
labels: protocol
---

**The change**

Which sections of docs/PROTOCOL.md change, and how: the bytes that are written, served or accepted, the labels, the
verdicts, the texts of warnings and system lines, the requests a client makes, or the server's status codes, headers
and bodies.

**Why**

**Guarantees**

How the change affects the guarantees (§0.3) and the non-guarantees (§0.4).

**Leakage**

What changes in the leakage table (§13): what the server, or anyone who reads its data, learns that it did not before,
and what it no longer learns.

**Existing data**

What happens to the rows, self-lane records, key bundles, images and directory records that are already stored, and
to what browsers keep locally. All of it must stay readable.

Pull requests do not edit docs/PROTOCOL.md directly: once the change is agreed here, the maintainer applies it to the
specification, and the implementation follows.
