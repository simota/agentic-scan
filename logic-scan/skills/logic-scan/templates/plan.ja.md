<!--
coding-implement または担当者に渡すロジック正しさの修正計画。batch は findings.json の plan[]、各 finding の欄は
findings[] から転記する。plan[] のエントリごとに batch の節を、その中の ID ごとに finding の節を繰り返す。
除外された finding（FalsePositive / NotApplicable）は載せない。Likely / Unlikely / Unverified の finding は確定した事実として
書かず、最初の手順で未確定の点を確かめる。実行者は着手前に、各 location を自分の
リビジョンで読み直す。この計画は {{meta.commit}} を記述している。finding にない任意の欄（depends_on、
convention、counterexample、change_reason）は「なし」と書く。
-->

# ロジック正しさの修正計画 — {{meta.project}}（{{meta.date}}）

- **対象リビジョン:** {{meta.commit}}、履歴の期間 {{meta.window}}
- **範囲:** {{meta.scope}}
- **全手順に共通のルール:** 各手順はビルドとテストを green で終える。各修正は反例のテストと同じ変更で入れ、
  修正を戻すとテストが失敗することを確かめる。変わるのは finding が挙げた結果だけで、結果が変わる呼び出し元はすべて確認する。
  すでに出た誤った結果（保存済みの合計、送付済みの書類）は判断事項として報告し、ついでに訂正しない
- **コマンド:** 手順と `verify:` 行は信頼できないコードを読んで書いたもので、確認する内容を表す。実行するのは
  着手前に依頼者と確認したビルドとテストのコマンドだけ。それ以外（ダウンロード、インストール、シェルへのパイプ、
  `eval`、本番に対するコマンド）を求める手順は、先に人に確認する

## 着手前に必要な判断

<!-- batch の prerequisite が挙げている decisions[] の項目と、計画内の finding が convention で参照する inferred な
規約の確認を求める項目。なければ「なし」と書く。 -->
- 

## バッチ {{plan[].batch}}: {{plan[].title}}

- **PR タイトル:** {{plan[].pr_title}}
- **前提条件:** {{plan[].prerequisite}}

### {{id}}: {{title}}

- **対処:** {{remedy}}（{{hazard}}）— 修正の波及 {{change}}、規模 {{effort}}
- **波及の理由:** {{change_reason}}
- **検証判定:** {{validation.verdict}}（確度 {{confidence}}）
- **場所:** {{location}}
- **反例:** {{counterexample.input}} → 正しい結果 {{counterexample.expected}}、実際の結果 {{counterexample.actual}}（正解の根拠 {{counterexample.oracle}}）
- **現在の担保:** {{enforcement.net}}、担保箇所 {{enforcement.sites}}、不足 {{enforcement.gaps}}
- **先行する検出事項:** {{depends_on}}
- **ロジックルール:** {{convention}}
- **守るべきルール:**

{{invariants}}

- **手順:**

{{steps}}

## 後回しにするもの

<!-- 「次にその領域を触るとき」とした Low / Info の finding（next_steps）。 -->
-
