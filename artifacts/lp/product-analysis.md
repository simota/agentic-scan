# プロダクト分析

## 概要

agentic-scan は、AI コーディングエージェント(Claude Code・Codex・Antigravity)が対象リポジトリを読んで診断するための 12 のスキル集。各スキルは観点ごとに独立し、共通の手順(RECON → CHECKLIST → REVIEW → VERIFY → REPORT。一部は PLAN を含む)で指摘を記録し、チャット要約・HTML ダッシュボード・レポートとして返す。

根拠: ルート `README.md`、各 `<skill>/README.md` の冒頭と "What it does" / "Install" 節。

## 確認できた事実(LP の訴求に使ったもの)

| 事実 | 根拠 |
|---|---|
| 12 スキル(security, infra-security, privacy, logic, data-integrity, bug, test-gap, architecture, performance, prune, ux, prompt) | ルート `README.md` の表 |
| 既定は読み取り専用。コードを編集せず、デプロイ済みシステムへ通信しない | 各 README 冒頭の注記 |
| 例外: logic-scan の REPRO、test-gap-scan と data-integrity-scan の GUARD、performance-scan のベンチマークは依頼と許可がある場合のみ | `logic-scan/README.md`, `test-gap-scan/README.md`, `data-integrity-scan/README.md`, `performance-scan/README.md` |
| infra-security-scan はクラウド API を呼ばず `terraform plan/apply` も実行しない | `infra-security-scan/README.md` |
| privacy-scan は法的助言ではない | `privacy-scan/README.md` |
| ux-scan は好みではなく基準で判定する(`padding: 13px` の例) | `ux-scan/README.md` |
| High / Medium を再検証(VERIFY)してから報告 | 各 README の "What it does" 図 |
| 出力: チャット要約、dashboard.html、report.md / report.html / PDF(スキルにより異なる)、findings.json | 各 README の図 |
| SARIF への書き出し、再スキャンとの比較、日本語・英語の出力 | 12 README すべてに記載(grep で確認) |
| Python 3.9+(一部 3.10+)、標準ライブラリのみ、PDF は Chrome / Chromium | 各 README の Requirements |
| `make link` で、インストール済みのホスト(claude / codex / agy)すべてにリンク | 各スキルの `Makefile`、ルート `Makefile` |
| `make demo` で同梱サンプルからダッシュボード生成 | 各 README、実行して確認 |
| サンプル指摘のタイトル(LP の 12 行の右列) | 各 `examples/findings.sample*.json` から抽出 |

## ターゲット

- 主: 自分のアプリのコードを AI エージェントと書いている開発者・テックリード。エージェントにレビューも任せたいが、「それらしいだけの指摘」では使えないと感じている人。
- 課題: 指摘に場所・根拠・終わりの条件がない。エージェントが勝手にコードを直す不安。観点(セキュリティ、UX、データ整合性…)ごとに道具がばらばら。
- 代替手段: 汎用のコードレビュー依頼、個別の静的解析ツール、人手のレビュー。
- 導入をためらう理由: コードを書き換えられる不安、本番やクラウドへの接触、セットアップの手間、結果の信頼性。
- 決め手: 既定の読み取り専用、検証済みの判定、ファイルと行つきの指摘、依存なし・`make link` のみ。

## 推測(リポジトリに根拠がないもの)

- 上記ペルソナと心理的障壁は推測。利用者データ・導入実績・満足度などはリポジトリに存在しないため、LP には載せていない。
- 料金・ライセンスの記載は見つからなかったため LP では触れていない。

## 差別化(確認できる範囲)

1. 観点ごとの専用スキル 12 種が、同じ手順と同じ報告書形式を持つ。
2. 検証(反証)を経た判定(Confirmed / Valid など)を指摘ごとに記録する。
3. 既定で読み取り専用。書き込みを伴う手順は依頼と許可がある場合だけ。
4. 外部パッケージ不要。
