# agentic-scan ランディングページ

agentic-scan(AI エージェント向けの、読み取り専用のレビュースキル 12 種)を紹介する静的 LP。

2026-11-19 に、ブランドを「ターミナル / エージェント」の方向で作り直した。

- ワードマークは `r--`(読み取り専用の権限の文字列)。
- 等幅の書体がブランドを担う。
- 色は、スキル自身のダッシュボードが使う重大度の色。
- ページ上の端末の出力は、すべて実際に実行したコマンドの結果である。
- 製品画面は、各スキルの `make demo` で生成した実物である。

## 実装場所と開き方

- ソース: `site/`(`index.html`、`styles.css`、`main.js`、`assets/`)
- 起動:

  ```sh
  cd site && python3 -m http.server 8765 --bind 127.0.0.1
  # http://127.0.0.1:8765/
  ```

- ビルド: 不要(依存パッケージもビルド工程もない)

## 最終評価

- 内部評価 89 / 100(作り直し後の推移は 64 → 78 → 82 → 86 → 89)。採点の根拠と、90 に届かなかった理由は `pdca-report.md` にある。
- Lighthouse(ラボ計測、ローカル配信): モバイルもデスクトップも、Performance / Accessibility / Best Practices / SEO がすべて 100。モバイルの LCP は 1.1s、CLS は 0。
- ui-deslop の検出器: 未解決の検出 0 件。

## 成果物

| ファイル | 内容 |
|---|---|
| `product-analysis.md` | プロダクト分析(前の版のまま。内容は今も有効) |
| `creative-strategy.md` | 作り直したコンセプト、署名、構成、CTA |
| `design-spec.md` | ワードマーク、色、書体、余白、動き、レスポンシブ |
| `implementation-report.md` | 変更したファイル、端末の出力の出どころ、CTA の遷移先 |
| `pdca-report.md` | 5 サイクル(R1〜R5)のスコアと改善の記録 |
| `qa-report.md` | 実ブラウザでの確認、Lighthouse、確かめていないこと |
| `screenshots/rebrand/` | 作り直した版の画像(WebP、合計 1.4MB)。`cycles/`、`final/`、`widths/` |
| `lighthouse/rebrand/` | 作り直した版の Lighthouse レポート(JSON と HTML) |
| `qa/transcripts/` | ページに載せた端末の出力の、元の実行結果 |
| `qa/scripts/rebrand/` | 撮影と確認に使ったスクリプト |

## 既知の制約

- GitHub のリポジトリは非公開。アクセス権のない訪問者は clone も GitHub のリンクも使えない(導入の節に明記した)。
- OGP の画像がない。公開 URL がないため、絶対 URL を設定できない。
- ダッシュボードの画面自体は、スキル側のエディトリアル調のまま。LP のブランドとは見た目が違う。
