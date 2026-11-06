<!--
1 件の finding を 1 件の issue として登録するテンプレート（1 根本原因 = 1 修正箇所 = 1 issue）。
scripts/issues.py が findings.json からこのテンプレートを埋めた下書きを作る。ここから書き始めず、その下書きを編集する。
各欄の {{field}} は findings.json の同名フィールドから転記する。空の任意欄は行ごと削除し、中身がすべて
空のセクション（参考がない場合の「参考」など）は見出しごと削除する。コードの識別子（`*sql.Tx`、
`order_items`）はバッククォートで囲み、Markdown で * や _ が解釈されないようにする。
場所は 1 つずつバッククォートで囲み、表のセル内では <br> で区切る。{{request}} は番号ごとに改行する。
確度が Environment-dependent なら、前提条件としきい値（scale_driver または impact から）と、関連する
limitations の項目を「未確定事項」に書く。
検証方法は static を「静的」、measured を「計測」と書く。step がなければ「（）」ごと省き、meta.commit が空なら UNKNOWN、location が配列なら 1 行に 1 つの
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
| 検証判定 | {{validation.verdict}}（検証方法: {{validation.method}}） |
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

<!-- 該当するエントリーポイントが複数ある場合はすべて列挙する（同じ根本原因なら同じ issue）。共有資源の
停止なら、停止を引き起こすワークロードと、待たされるワークロードの両方を書く。 -->

## 根拠

{{validation.evidence}}

<!-- 計測した場合はコメント記号を外して以下を残す（実行環境: {{measurement.environment}}）。計測していなければこのブロックごと削除する
## 計測ログ

修正前: {{measurement.before.result}}

```text
$ {{measurement.before.command}}
{{measurement.before.log}}
```

修正後: {{measurement.after.result}}

```text
$ {{measurement.after.command}}
{{measurement.after.log}}
```
-->

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
