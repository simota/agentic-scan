<!--
1 件の finding を 1 件の issue として登録するテンプレート（1 根本原因 = 1 修正箇所 = 1 issue）。
各欄の {{field}} は findings.json の同名フィールドから転記する。空の任意欄は行ごと削除する。
場所は 1 つずつバッククォートで囲み、表のセル内では <br> で区切る。{{request}} は番号ごとに改行する。
確度が Environment-dependent なら、前提条件としきい値（scale_driver または impact から）と、関連する
limitations の項目を「未確定事項」に書く。
step がなければ「（）」ごと省き、meta.commit が空なら UNKNOWN、location が配列なら 1 行に 1 つの
path:line、参考の title が空なら URL をリンク文字列にする。

登録前に確認すること:
- 計測していないレイテンシやメモリの数値を書かない。代わりにコストモデルを書く
- ソース抜粋はリポジトリと同じ機密区分になる。issue の閲覧範囲がリポジトリより広いなら貼らない
-->

**タイトル:** [{{severity}}] {{title}} ({{id}})

## 概要

| 項目 | 値 |
|---|---|
| ID | {{id}} |
| 深刻度 | {{severity}} |
| 確度 | {{confidence}} |
| 検証判定 | {{validation.verdict}}（方法: {{validation.method}}） |
| 観点 | {{category}}（{{step}}） |
| 場所 | {{location}} |
| 対象リビジョン | {{meta.commit}} |
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

## 何が起きるか

{{impact}}

- **ワークロード:** {{workload}}
- **規模の要因:** {{scale_driver}}
- **コストモデル:** {{cost_model}}
- **違反しているバジェット:** {{budget}} — {{budgets[id=budget].statement}}

## 再現手順（静的）

{{request}}

**対照（バジェットが守られている経路）:** {{contrast}}

<!-- 該当するエントリーポイントが複数ある場合はすべて列挙する（同じ根本原因なら同じ issue）。 -->

## 根拠

{{validation.evidence}}

<!-- 計測した場合: {{measurement.command}}（{{measurement.environment}}）→ {{measurement.result}} -->

## 修正方針

{{fix}}

- **回帰テストで確認すること:** {{regression_test}}

## 参考

- [{{references[].title}}]({{references[].url}})

## 未確定事項

<!-- 静的解析では確認できない条件（本番のデータ量、デプロイ先のインデックス、プールサイズなど）。 -->
- 

## 対応完了の条件

- [ ] 修正がマージされた
- [ ] 修正前に失敗し、修正後に成功する決定的な回帰チェックが追加された
- [ ] 対象経路の結果が変わらないこと（positive control）を確認した
- [ ] findings.json の `status` を `Fixed` に更新した
