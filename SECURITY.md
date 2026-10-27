# Security policy

segv.sh is an end-to-end encrypted messenger, and reports about its cryptography, its protocol or this implementation
are very welcome.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: on the repository's **Security** tab, choose **Report a
vulnerability**, or go to <https://github.com/sizumita/segv.sh/security/advisories/new>. Please do not report
vulnerabilities in public issues, pull requests or discussions.

A useful report says:

- what an attacker can do, and what they need for it: only the public data, control of the server, membership of a
  conversation, or something else (the adversaries are defined in
  [docs/PROTOCOL.md §0.2](docs/PROTOCOL.md#02-adversaries));
- whether the problem lies in the specification ([docs/PROTOCOL.md](docs/PROTOCOL.md)) or only in this
  implementation;
- the affected part (cryptographic core, client engine, UI, Worker, Durable Objects or directory) and the commit;
- how to reproduce it, ideally as a test or a proof of concept against a local instance.

Test against your own instance ([docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)), never against other people's accounts or
data on <https://segv.sh>, and give the maintainer reasonable time to fix the problem before you disclose it.

## Scope

In scope:

- the protocol, and anything that breaks a guarantee it states
  ([docs/PROTOCOL.md §0.3](docs/PROTOCOL.md#03-guarantees-in-stage-1));
- the client, the Worker, the Durable Objects and the configuration in this repository;
- the deployment at <https://segv.sh>, where the problem lies in this code or its configuration.

Some limits are deliberate and documented in [docs/PROTOCOL.md §0.4](docs/PROTOCOL.md#04-non-guarantees) and
[§13](docs/PROTOCOL.md#13-leakage), and in [docs/DESIGN.md](docs/DESIGN.md) §3. Within what those sections describe,
they are not vulnerabilities: for example, the operator learning the social graph, the operator omitting rows without
the clients being able to prove it, the lack of forward secrecy once a passkey, recovery code or account key leaks, or
malicious JavaScript served by the operator. Going beyond them is in scope: for example, omitting rows without
tripping a detection that the specification promises, or learning from the public data something that the leakage
table says stays hidden.

Out of scope:

- flooding the deployment at <https://segv.sh> with traffic;
- attacks that need an already compromised device or browser;
- problems in third-party services, such as Cloudflare or passkey providers; please report those to the vendor.

## Supported versions

There are no versioned releases. Security fixes go to the `main` branch and to the deployment at <https://segv.sh>.
