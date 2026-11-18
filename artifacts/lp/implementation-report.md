# 実装レポート(ターミナル / エージェント版)

## 変更したファイル

| ファイル | 変更 |
|---|---|
| `site/index.html` | 全面的に書き直した。構成は hero、skills、verify、output、install、faq、footer |
| `site/styles.css` | 全面的に書き直した。トークンの定義、ライトとダーク、レスポンシブ |
| `site/main.js` | コピーボタンとタブだけにした。動作は前の版と同じ。読み込まなくてもページは読める |
| `site/assets/favicon.svg` | `r--` のマークに変えた |
| `site/assets/security-scan-crop*.webp` | 削除した(新しいページでは使わない) |

ダッシュボードの画像(`assets/*-scan*.webp`)は、前の版のものをそのまま使う。各スキルの `make demo` で生成した実際の画面である。


## 使った技術

HTML、CSS(カスタムプロパティ、コンテナクエリの `cqi`)、vanilla JS の 1.7KB だけ。依存パッケージ、Web フォント、ビルド工程はない。

## 端末の出力の出どころ

ページ上の出力ブロックは、次のコマンドを実際に実行した出力そのものである。`artifacts/lp/qa/transcripts/` に保存したものと、ページから抜き出した文字列が完全に一致することを確かめた(3 件とも MATCH)。

| 場所 | 実行したコマンド(作業ディレクトリ) | 保存先 |
|---|---|---|
| Hero の台帳 | `jq -r '.findings[] \| [.id, .severity, .validation.verdict, .location] \| @tsv' security-scan/examples/findings.sample.ja.json \| column -t`(リポジトリの直下) | `qa/transcripts/hero-jq.txt` |
| skills の目次 | `make list`(リポジトリの直下) | `qa/transcripts/make-list.txt` |
| output | `make demo NO_PDF=1 DEMO_OUT=../out/security-scan`(`security-scan/`)。生成した `out/` はすぐに削除した | `qa/transcripts/make-demo.txt` |

それ以外の、事実の出どころ:

- 重大度の色: `report_assets/dashboard.css`
- F-004 の根拠の引用: `findings.sample.ja.json` の `validation.evidence`
- 各スキルの工程: 各 README の工程の行
- 各スキルの指摘例: 各スキルの `examples/findings.sample*.json` の title と severity(12 件とも照合済み)

## 主な CTA の遷移先

| CTA | 遷移先 | 動作 |
|---|---|---|
| ヘッダーの「導入する」 | `#install` | 確認済み(押したあと #install が画面内に入る) |
| 「導入手順を見る」 | `#install` | 確認済み |
| 「出力サンプルへ」 | `#output` | 確認済み |
| コピー(clone) | クリップボードに `git clone …\ncd agentic-scan` | 確認済み(中身が一致) |
| コピー(link) | クリップボードに `make link` | 確認済み(中身が一致) |
| 「GitHub でリポジトリを見る」 | `https://github.com/simota/agentic-scan` | 非公開のため、権限のない人には 404 |
| `make list` の各行 | `#s-<skill>` | 12 件とも行き先の節があることを確認済み |

## 起動とビルド

```sh
cd site && python3 -m http.server 8765 --bind 127.0.0.1
# http://127.0.0.1:8765/
```

ビルドは不要。

## 既存のものへの影響

触ったのは `site/` と `artifacts/lp/` の中だけで、各スキルのディレクトリとルートの README / Makefile には手を入れていない。コミットもしていない。
