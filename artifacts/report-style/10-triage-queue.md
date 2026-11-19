# Pattern 10: トリアージキュー (`10-triage-queue.html`)

## コンセプト
診断結果を「読んだ直後にどう捌くか」という実務フローに振り切った、4 レーンの行動別カンバンボード＋チケット詳細インスペクタ。`FIX NOW`（修正計画）／`VERIFY FIRST`（先に検証）／`CLOSED`（対応済・受容）／`EXCLUDED`（誤検知・除外）の 4 列に全件を自動振り分けし、カード選択で直下のインスペクタから根拠確認と Issue / LLM 向けコピーまで完結する。

## なぜ agentic-scan らしいか
- **「決めるのは人です (`decide`)」の UI 化**: `render.py` がすでに内部で計算している `fix_now` / `verify_first` / `excluded` の振り分けを、一覧テーブルの補助ではなくページ骨格そのものに昇格させている。
- **read-only の信頼性と実務の橋渡し**: `r--` ワードマーク・クールグレー地・等幅 ID/パスで「勝手に直さない」節度を保ちながら、選んだチケットを 1 クリックで LLM / Issue 用にコピーできる導線を置き、読み取り専用スキャンから次の修正フェーズへ自然につなぐ。

## 他スキルへの横展開方法
- **4 レーン定義のスキル別マッピング**:
  - `security-scan` / `infra-security-scan` / `privacy-scan`: `FIX NOW` / `VERIFY FIRST` / `CLOSED` / `EXCLUDED`（そのまま共通）
  - `prune-scan`: `SAFE TO DELETE`（即削除可） / `CHECK CALLERS`（呼び出し確認） / `KEEP`（保持） / `EXCLUDED`
  - `prompt-scan`: `DEFECT / FIX NOW`（欠陥） / `IMPROVEMENT`（改善提案） / `VERIFY FIRST` / `EXCLUDED`
  - `ux-scan` / `performance-scan`: `HIGH IMPACT` / `VERIFY / MEASURE` / `ACCEPTED` / `EXCLUDED`
- **区分タグ (`code` / `deps`)**: 他スキルでは対象レイヤーや対象画面・モジュール名に差し替えてそのまま使える。

## 既存 `render.py`・`dashboard.css` に入れるときの変更範囲と工数感
- **変更範囲**:
  - `render.py`: 既存の `R.queue`（`fix_now` / `verify_first` 判定済み）と `F` / `ALL` を 4 つの配列に分けて描画するだけなので、Python 側のデータモデル変更はほぼ不要（既存 `action(f)` 関数と `findingMarkdown(f)` コピー関数をそのまま流用できる）。
  - `dashboard.css`: 既存の `.priority-list` と `.tablewrap` の代わりに `.board`（4 列グリッド）と `.inspector`（詳細パネル）を定義し、LP のクールグレー・等幅・サンセリフ体系へ刷新。
- **工数感**: 中（1〜1.5 日 / 1 スキルあたり。JS のコピー機能やアクション判定ロジックが既存 `render.py` にあるため、実装リスクは低い）。

## 弱点
- **大量の指摘（30 件以上）での縦伸び**: 1 レーン（特に `VERIFY FIRST`）に指摘が集中すると、カンバン列が縦に長くなり、直下のインスペクタまでの視線移動・スクロールが増える（実用時はレーン内スクロールや検索バーの追加が必要）。
- **印刷 (PDF) 時のカード分割**: 4 列カンバンは印刷用紙に収まらないため、印刷時は 2 列（または `assessment.html` 側の縦一覧）へフォールバックする必要がある。
