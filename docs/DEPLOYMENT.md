# Deployment

segv.sh runs on Cloudflare: one Worker with static assets, five Durable Object classes with SQLite storage, a D1
database, an R2 bucket and the Workers rate-limiting binding. The repository's `wrangler.jsonc` configures the
deployment at <https://segv.sh>; to run your own instance, change the values that the steps below name.

## Decide these first

Some settings cannot change once people use a deployment.

- **The domain.** The passkey relying party ID is the host name of the page, and every PRF output is bound to it. If
  the domain changes after users register, their passkeys no longer unlock their accounts. Choose the final domain
  before the first registration, and serve the app only there: `workers_dev` and `preview_urls` are disabled, and on
  any host name outside `APP_HOSTS` the Worker redirects pages to the canonical host and refuses API requests.
- **`DELTA_S` and `INBOX_SLOT_S`.** Δ (the granularity of row times) and Δin (the length of an inbox slot) are
  constants of a deployment. They must not change once any Durable Object has stored data; a different value needs a
  new deployment with empty storage. `SKEW_S` must not change within an era.
- **`SRV_KEY`.** Clients pin the server's signing key the first time they see it, and show the warning "the server's
  signing key changed" if it ever differs. Keep this secret for the life of the deployment.
- **`ROUTE_KEY`.** It keys the routing of rows to shards and the routing commitment that the API publishes for each
  era. Keep it for the life of the deployment.
- **`E_FIRST`.** Set it to the current era before the first deployment. Requests for earlier eras are answered as
  empty without reaching storage, so never raise it once the deployment holds data.

## Requirements

- A Cloudflare account that also holds the DNS zone of your domain: the Worker is attached to the domain as a Custom
  Domain.
- Wrangler, which `npm install` provides. Sign in with `npx wrangler login`.

## Steps

1. Create the D1 database, and put its id into `d1_databases[0].database_id` in `wrangler.jsonc`:

   ```bash
   npx wrangler d1 create segv
   ```

2. Create the R2 bucket. If you choose another name, change `r2_buckets[0].bucket_name`.

   ```bash
   npx wrangler r2 bucket create segv-blobs
   ```

3. Apply the D1 migrations:

   ```bash
   npx wrangler d1 migrations apply DB --remote
   ```

4. Edit the rest of `wrangler.jsonc`:
   - `name`: the name of your Worker;
   - `routes`: `[{ "pattern": "<your domain>", "custom_domain": true }]`;
   - `vars.APP_HOSTS`: your domain first (the canonical host), then `localhost` for local development and the tests;
   - `vars.E_FIRST`: the current era, which this prints:

     ```bash
     node -e 'console.log(Math.floor((Date.now() - 1767639600000) / 604800000))'
     ```

   - `ratelimits[].namespace_id`: ids that no other Worker in your account uses.

5. Set the two server secrets, each 32 random bytes in base64url. For each one, generate a value with the first
   command and paste it when Wrangler asks for it:

   ```bash
   node -e 'console.log(require("node:crypto").randomBytes(32).toString("base64url"))'
   npx wrangler secret put ROUTE_KEY
   npx wrangler secret put SRV_KEY
   ```

6. Deploy:

   ```bash
   npm run deploy
   ```

7. Open `https://<your domain>/api/v2/params`. It shows the deployment parameters, the current era, `efirst` and the
   server's public key `srvKey`. A 503 `server misconfigured` means that a secret is missing or a variable is invalid.

### Notifications (optional)

Web Push is off until you set its secrets. With it on, params report `push`, and users can turn notifications on per
device ([PROTOCOL.md §9.8](PROTOCOL.md)).

1. Set the VAPID key (a P-256 private scalar, 32 bytes base64url), the key that seals the stored registrations
   (32 random bytes base64url), and a contact the push services can reach:

   ```bash
   node -e 'const {generateKeyPairSync}=require("node:crypto");console.log(generateKeyPairSync("ec",{namedCurve:"P-256"}).privateKey.export({format:"jwk"}).d)'
   npx wrangler secret put VAPID_SK
   node -e 'console.log(require("node:crypto").randomBytes(32).toString("base64url"))'
   npx wrangler secret put PUSH_KEY
   npx wrangler secret put VAPID_SUB
   ```

   `VAPID_SUB` is a `mailto:` or `https:` URI. Keep `VAPID_SK` and `PUSH_KEY` for the life of the deployment: a new
   `VAPID_SK` breaks every subscription until its device subscribes again, and a new `PUSH_KEY` invalidates every
   registration (devices register again at their next start).

2. Check `https://<your domain>/api/v2/params`: it now has `push` and `pow.push`. If not, the Worker's logs name the
   push setting that is missing or invalid (never its value); an invalid push setting turns push off and changes
   nothing else.

## Configuration reference

### Variables

| Name           | Value at segv.sh    | Meaning                                                                                                                                                                                      |
| -------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POW_REGISTER` | 20                  | Proof-of-work difficulty (leading zero bits) for registration                                                                                                                                |
| `POW_WRAP`     | 18                  | Difficulty for adding a key wrap (a passkey or the recovery code)                                                                                                                            |
| `POW_PUT`      | 16                  | Base difficulty for writing rows; larger bodies need more                                                                                                                                    |
| `POW_INBOX`    | 18                  | Base difficulty for posting inbox invites; larger bodies need more                                                                                                                           |
| `POW_BLOB`     | 18                  | Base difficulty for uploading an image or a key bundle; larger uploads need more                                                                                                             |
| `DELTA_S`      | 10                  | Δ in seconds, 1–3600: the granularity of row times. It must divide 604 800 (one week). Constant for the deployment                                                                           |
| `SKEW_S`       | 2                   | SKEW in seconds, 0–60: the bound on clock differences between server components. Constant within an era                                                                                      |
| `INBOX_SLOT_S` | 10                  | Δin in seconds, 1–3600: the length of an inbox slot. Constant for the deployment                                                                                                             |
| `E_FIRST`      | 42                  | The era of the first deployment                                                                                                                                                              |
| `APP_HOSTS`    | `segv.sh,localhost` | The host names the Worker answers on, comma-separated; the first is canonical. Pages on other hosts are redirected to it (308), and API requests are refused (421). Empty disables the check |

A variable that is present but invalid (not a decimal number, out of range, or a `DELTA_S` that does not divide
604 800) makes every `/api/v2/*` request answer 503 `server misconfigured`. Clients refuse a proof-of-work base above 26.

### Secrets

| Name        | Value                                           | Used for                                                           |
| ----------- | ----------------------------------------------- | ------------------------------------------------------------------ |
| `ROUTE_KEY` | 32 bytes, base64url without padding             | Routing rows to shards, and the per-era routing commitment         |
| `SRV_KEY`   | 32-byte Ed25519 seed, base64url without padding | Signing write receipts and checkpoints; clients pin its public key |
| `VAPID_SK`  | P-256 scalar, 32 bytes, base64url (optional)    | Signing pushes (RFC 8292); its public key is params `push.vapid`   |
| `PUSH_KEY`  | 32 bytes, base64url (with `VAPID_SK`)           | Sealing the stored notification registrations                      |
| `VAPID_SUB` | `mailto:` or `https:` URI (with `VAPID_SK`)     | The contact sent to push services                                  |

Optional push variables: `PUSH_HOSTS` (the push service hosts that may receive pushes; default Apple, Google, Mozilla
and Microsoft), `POW_PUSH` (20), `PUSH_MAX_SUBS` (100 000) and `PUSH_DAY_SUBS` (2 000).

### Rate limits

Each limit counts requests per IPv4 address or IPv6 /64 over 60 seconds, and the keys are never stored.

| Binding    | Limit | Requests                                                                                    |
| ---------- | ----- | ------------------------------------------------------------------------------------------- |
| `RL_WRITE` | 60    | Registration, key wraps and row writes                                                      |
| `RL_INBOX` | 10    | Inbox posts, each of up to 32 invites                                                       |
| `RL_BLOB`  | 20    | Uploads                                                                                     |
| `RL_READ`  | 600   | Row reads, inbox reads, directory reads, downloads, checkpoints, the feed and the WebSocket |
| `RL_RING`  | 60    | Rings after a text or an image (notifications)                                              |

### Logs

`observability.logs.invocation_logs` is off on purpose. Invocation logs would keep the URL of every request, which can
contain handles, credential ids and blob ids, together with request metadata. The Worker's own `console.error` lines
carry none of these. Keep it that way.

## Staging

Run staging as a separate deployment, with its own Worker name, D1 database, R2 bucket, secrets and `E_FIRST`, and its
own host name in `routes` and `APP_HOSTS`. Passkeys registered on staging work only there.

## Updating

- Deploy new code with `npm run deploy`.
- When a change adds a D1 migration, apply it with `npx wrangler d1 migrations apply DB --remote` before deploying the
  code that needs it. Changes to Durable Object classes are declared in `migrations` in `wrangler.jsonc`.
- Check a change to `wrangler.jsonc` with `npm run build` followed by `npx wrangler deploy --dry-run` before you deploy
  it.
