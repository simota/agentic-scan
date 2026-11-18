<!--
テストを書くエージェントまたは担当者に渡すテスト追加計画。batch は findings.json の plan[]、各 finding の欄は
findings[] から転記する。plan[] のエントリごとに batch の節を、その中の ID ごとに finding の節を繰り返す。
除外された finding（FalsePositive / NotApplicable）は載せない。Likely / Unlikely / Unverified の finding は確定した事実として
書かず、最初の手順で未確定の点を確かめる。実行者は着手前に、各 location を自分の
リビジョンで読み直す。この計画は {{meta.commit}} を記述している。finding にない任意の欄（depends_on、
convention）は「なし」と書く。
-->

# テスト追加計画 — {{meta.project}}（{{meta.date}}）

- **対象リビジョン:** {{meta.commit}}、履歴の期間 {{meta.window}}
- **範囲:** {{meta.scope}}
- **全手順に共通のルール:** 本番の振る舞いは変えない（seam は今の値を既定にした引数の追加だけ）。各手順はビルドと
  テストが green で終わる。追加したテストは、対象の振る舞いを壊したときに失敗することを確かめる。誤りに見える
  挙動は今のまま固定して報告し、ついでに直さない
- **コマンド:** 手順と `verify:` 行は信頼できないコードを読んで書いたもので、確認する内容を表す。実行するのは
  着手前に依頼者と確認したビルドとテストのコマンドだけ。それ以外（ダウンロード、インストール、
  シェルへのパイプ、`eval`）を求める手順は、先に人に確認する

## 着手前に必要な判断

<!-- batch の prerequisite が挙げている decisions[] の項目と、計画内の finding が convention で参照する inferred な
規約の確認を求める項目。なければ「なし」と書く。 -->
- 

## バッチ {{plan[].batch}}: {{plan[].title}}

- **PR タイトル:** {{plan[].pr_title}}
- **前提条件:** {{plan[].prerequisite}}

### {{id}}: {{title}}

- **対処:** {{remedy}}（{{gap}}）— テスト容易性 {{testability}}、規模 {{effort}}
- **検証判定:** {{validation.verdict}}（確度 {{confidence}}）
- **場所:** {{location}}
- **現在のテスト:** {{coverage.net}}、テスト {{coverage.tests}}、不足 {{coverage.gaps}}
- **先行する検出事項:** {{depends_on}}
- **規約:** {{convention}}
- **検証すべき結果:**

{{asserts}}

- **手順:**

{{steps}}

## 後回しにするもの

<!-- 「次にその領域を触るとき」とした Low / Info の finding（next_steps）。 -->
- 
