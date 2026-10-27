# segv.sh

パスキー（WebAuthn PRF）で鍵を解錠し、1:1 / グループでテキストと画像をエンドツーエンド暗号化して送るミニマルなメッセンジャー。
**サーバーの中身はすべて公開**：保存されるのは公開データだけで、誰でも読める。クライアントは自分宛ての行のラベルを計算し、その行だけを取得して復号する。

> **現在の状態:** プロトコル v2（stage 1）を v1 の置き換えとして実装中。登録・サインイン、1:1 とグループの作成、
> テキストと画像の送受信、リロードや別端末での復元、メンバーの追加・削除と退出（鍵の更新）が動く（M7）。
> スナップショット、整合性チェック（チェックポイント・受領証）、リンクはまだ（M6c 残り・M8・M10）。

- バイト単位のプロトコル仕様（v2）: [docs/PROTOCOL-v2.md](docs/PROTOCOL-v2.md)、実装計画: [docs/STAGE1-PLAN.md](docs/STAGE1-PLAN.md)
- 設計の理由・保証すること/しないこと: [docs/DESIGN.md](docs/DESIGN.md)（v1 時点の内容。v2 向けの書き直しは M9）

## 構成

| 場所                              | 中身                                                                                                              |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `src/lib/proto.ts`                | プロトコルの暗号コアと符号化（クライアント・Worker・Durable Object で共有）。`@noble/*` のみ使用                  |
| `src/lib/wire.ts`                 | API のバイナリ形式（put / get / inbox / feed / realtime フレーム）の厳格なエンコーダ・デコーダ                    |
| `src/client/`                     | ブラウザ専用のエンジン（`engine.ts`、会話の `messaging.ts` ほか）、パスキー/PRF、セッション、画像                 |
| `src/routes/`, `src/components/`  | Qwik v2 の UI                                                                                                     |
| `src/server/`                     | Worker の API（`/api/v2/*`）、Durable Objects（Shard / BlobReg / Inbox / Realtime / Checkpoint）、D1 ディレクトリ |
| `src/entry.cloudflare-workers.ts` | Worker エントリ（`/api/*` → API、それ以外 → Qwik SSR）                                                            |
| `migrations/`                     | D1 スキーマ（ディレクトリ: user / wrap / dirlog）                                                                 |
| `src/lib/*.test.ts`               | 暗号コアとバイナリ形式の単体テスト（独立実装との突き合わせ・改ざん・既知解ベクトル・ファジング）                  |
| `test/worker/`                    | Workers ランタイム上の API / Durable Object / ディレクトリのテスト                                                |
| `test/engine/`                    | インメモリの偽サーバー `FakeWorld` と、その上でエンジンを動かすテスト（アカウント、会話、復元、メンバー変更）     |
| `test/e2e/`                       | Playwright + 仮想認証器（PRF 対応）による v2 の E2E テスト（登録、会話、復元、別端末、公開データの監査）          |

技術スタック: Vite+ (`vite-plus`) / Qwik v2 RC / Cloudflare Workers + D1 + Durable Objects + R2 / `@noble/curves`, `@noble/post-quantum` (X-Wing), `@noble/ciphers`, `@noble/hashes`。

## 開発

```bash
npm install
npm run db:migrate:local   # ローカル D1 にスキーマを適用
npm run dev                # vp dev（workerd 上で SSR + API + DO が動く）
```

`http://localhost:<port>` を開く（パスキーの RP ID は `localhost`）。サーバーの秘密鍵 `ROUTE_KEY` と `SRV_KEY`（どちらも 32 バイトの base64url）を `.dev.vars` に置く（gitignore 済み。無いと `/api/v2/*` は 503）。

## テスト

```bash
npx vp test run            # 単体（暗号コア・バイナリ形式）+ Workers ランタイム（API / DO / D1）+ エンジン（FakeWorld）
npm run build              # 型チェック・lint 込みの本番ビルド
```

`npm run test:e2e` は本番ビルドと `wrangler dev` を立ち上げ、ヘッドレス Chromium で主要なフロー（画像、メンバーの削除と
退出を含む）と公開データの監査を流す。

## デプロイ（Cloudflare）

1. `npx wrangler d1 create segv` で作った `database_id` を `wrangler.jsonc` に書く。
2. `npx wrangler r2 bucket create segv-blobs`
3. `npx wrangler d1 migrations apply DB --remote`
4. `npx wrangler secret put ROUTE_KEY` と `npx wrangler secret put SRV_KEY`（どちらも 32 バイトの乱数を base64url で）。
5. `segv.sh` のゾーンを同じ Cloudflare アカウントに置き、`wrangler.jsonc` に `"routes": [{ "pattern": "segv.sh", "custom_domain": true }]` を追加（`workers_dev` / `preview_urls` は意図的に無効。`APP_HOSTS` 以外のホストはリダイレクトされる）。
6. `E_FIRST`（最初のデプロイの era）を `wrangler.jsonc` の `vars` で確認する。
7. `npm run deploy`

**重要: 最初のユーザーが登録する前に本番ドメインを確定させること。** パスキーと PRF 出力は RP ID（ドメイン）に紐づくので、後からドメインを変えると全員が鍵を失う。ステージングは別の Worker 名・別の D1/R2・別の `APP_HOSTS` で分けて動かす。

Proof of Work の難易度は `wrangler.jsonc` の `vars`（`POW_REGISTER` / `POW_WRAP` / `POW_PUT` / `POW_INBOX` / `POW_BLOB`）で、時間パラメータは `DELTA_S`（604800 を割り切る値）/ `SKEW_S` / `INBOX_SLOT_S` で調整する。
