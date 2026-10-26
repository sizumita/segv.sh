# segv.sh

パスキー（WebAuthn PRF）で鍵を解錠し、1:1 / グループでテキストと画像をエンドツーエンド暗号化して送るミニマルなメッセンジャー。
**サーバーの中身はすべて公開**：誰でも全ログを読める。クライアントは全行を取得し、自分宛てだけをローカルで見つけて復号する。

- 設計の理由・保証すること/しないこと: [docs/DESIGN.md](docs/DESIGN.md)
- バイト単位のプロトコル仕様: [docs/PROTOCOL.md](docs/PROTOCOL.md)

## 構成

| 場所                              | 中身                                                                                               |
| --------------------------------- | -------------------------------------------------------------------------------------------------- |
| `src/lib/proto.ts`                | プロトコルの暗号コア（クライアントと Worker で共有）。`@noble/*` のみ使用                          |
| `src/client/`                     | ブラウザ専用のエンジン（パスキー/PRF、ログ同期とハッシュチェーン検証、招待スキャン、送受信、画像） |
| `src/routes/`, `src/components/`  | Qwik v2 の UI                                                                                      |
| `src/server/`                     | Worker の API、Durable Object `LogDO`（権威ある公開ログ + WebSocket 配信）、D1 インデックス、R2    |
| `src/entry.cloudflare-workers.ts` | Worker エントリ（`/api/*` → API、それ以外 → Qwik SSR）                                             |
| `migrations/`                     | D1 スキーマ                                                                                        |
| `src/lib/proto.test.ts`           | 暗号コアの単体テスト（往復・改ざん・既知解ベクトル）                                               |
| `test/worker/`                    | Workers ランタイム上の API / Durable Object テスト                                                 |
| `test/engine/`                    | 本物のクライアントエンジンを偽サーバー相手に動かす攻撃シナリオ回帰テスト                           |
| `test/e2e/`                       | Playwright + 仮想認証器（PRF 対応）による E2E テスト                                               |

技術スタック: Vite+ (`vite-plus`) / Qwik v2 RC / Cloudflare Workers + D1 + Durable Objects + R2 / `@noble/curves`, `@noble/post-quantum` (X-Wing), `@noble/ciphers`, `@noble/hashes`。

## 開発

```bash
npm install
npm run db:migrate:local   # ローカル D1 にスキーマを適用
npm run dev                # vp dev（workerd 上で SSR + API + DO が動く）
```

`http://localhost:<port>` を開く（パスキーの RP ID は `localhost`）。

## テスト

```bash
npx vp test run            # 単体（暗号コア）+ Workers ランタイム（API/DO）+ エンジン（攻撃シナリオ）
npm run test:e2e           # ビルド → wrangler dev → Chromium の仮想パスキー（PRF）で E2E
npm run build              # 型チェック・lint 込みの本番ビルド
```

## デプロイ（Cloudflare）

1. `npx wrangler d1 create segv` で作った `database_id` を `wrangler.jsonc` に書く。
2. `npx wrangler r2 bucket create segv-blobs`
3. `npx wrangler d1 migrations apply DB --remote`
4. `segv.sh` のゾーンを同じ Cloudflare アカウントに置き、`wrangler.jsonc` に `"routes": [{ "pattern": "segv.sh", "custom_domain": true }]` を追加（`workers_dev` / `preview_urls` は意図的に無効。`APP_HOSTS` 以外のホストはリダイレクトされる）。
5. `npm run deploy`

**重要: 最初のユーザーが登録する前に本番ドメインを確定させること。** パスキーと PRF 出力は RP ID（ドメイン）に紐づくので、後からドメインを変えると全員が鍵を失う。ステージングは別の Worker 名・別の D1/R2・別の `APP_HOSTS` で分けて動かす（本番のログに別ドメインのパスキーを混ぜない）。

Proof of Work の難易度は `wrangler.jsonc` の `vars`（`POW_REGISTER` / `POW_WRAP` / `POW_APPEND` / `POW_BLOB`）で調整できる。
