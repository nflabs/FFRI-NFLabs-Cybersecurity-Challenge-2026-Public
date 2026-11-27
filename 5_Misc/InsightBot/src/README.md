# InsightBot — 動作検証手順

## 構成

- `ollama` サービス: `qwen2.5-coder:3b-instruct` をイメージへ焼き込み（runtime はインターネット不要）。
- `web` サービス: Flask + SQLite。`/`(UI), `/ask`(質問API), `/reset`(DB初期化), `/health`。

## ビルドと起動

```bash
cd 5_Misc/InsightBot/src
docker compose up --build
```

- 初回はモデル焼き込みのため時間がかかります（ビルド時にインターネット到達が必要）。
- 起動後、ブラウザで `http://localhost:25002/` を開くとチャット UI が表示されます。
- 疎通確認: `curl -s http://localhost:25002/health` → `{"ok": true}`

## リセット

`POST /reset` で DB を初期状態へ再生成します。書き込み系の別解で汚れても復旧できます。
既定では 600 秒ごとにも自動リセットします（`RESET_INTERVAL_SEC`）。

## テスト

`web/tests/` に2種類のテストがあります（いずれも追加依存なし。イメージには同梱しません）。

```bash
cd 5_Misc/InsightBot/src/web

# 1) 防御ガードのユニットテスト（LLM/サーバ不要・決定論的）
#    「意図した大文字化回避でのみフラグが取れ、素直な経路では取られない」ことを検証。
python3 -m unittest tests.test_guardrails -v

# 2) システム固有テスト（SentinelOps テーマ）
#    スキーマ/ダミーデータ/規約(RFC予約帯IP・CVE形式)/機密配置を決定論的に検証（サーバ不要）＋
#    UI の提案チップが全て実サーバで有効に動くこと（＝選べる例は必ず動く）を検証（サーバ必要）。
python3 -m unittest tests.test_sentinelops -v

# 3) 統合テスト（docker compose up 済みで http://localhost:25002 が応答すること）
#    正常系・攻撃チェーン到達・素直な一発質問での非漏洩（難易度ガード）を検証。
python3 -m unittest tests.test_integration -v
#    別ホストなら: INSIGHTBOT_URL=http://<host>:25002 python3 -m unittest tests.test_integration -v

# まとめて実行:
python3 -m unittest discover -s tests -v
```
