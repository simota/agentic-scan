<!--
1 件の finding を 1 件の issue として登録するテンプレート（1 根本原因 = 1 修正箇所または 1 設計判断 = 1 issue）。
各欄の {{field}} は findings.json の同名フィールドから転記する。空の任意欄は行ごと削除する。

登録前に確認すること:
- 好みではなく、不具合または変更コストを書く。ルールの根拠（ADR、lint 設定、多数派のパターン）を示す
- ソース抜粋はリポジトリと同じ機密区分になる。issue の閲覧範囲がリポジトリより広いなら貼らない
-->

**タイトル:** [{{severity}}] {{title}} ({{id}})

## 概要

| 項目 | 値 |
|---|---|
| ID | {{id}} |
| 深刻度 | {{severity}} |
| 確度 | {{confidence}}（Environment-dependent なら、前提となる条件を「未確定事項」に書く） |
| 検証判定 | {{validation.verdict}}（方法: {{validation.method}}） |
| 観点 | {{category}}（{{step}}） |
| 場所 | `{{location}}` |
| 対象リビジョン | {{meta.commit}} |
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

## 何が起きるか

{{impact}}

- **シナリオ:** {{scenario}}
- **影響範囲:** {{blast_radius}}
- **破られている設計ルール:** {{rule}}

## 追跡

{{trace}}

**対照（ルールが守られているモジュールや経路）:** {{contrast}}

<!-- 該当する呼び出し箇所や書き込み元が複数ある場合はすべて列挙する（同じ根本原因なら同じ issue）。 -->

## 根拠

{{validation.evidence}}

<!-- 解析した場合: {{analysis.tool}} `{{analysis.command}}` → {{analysis.result}} -->

## 修正方針

{{fix}}

- **適合性チェック（fitness function）:** {{guard}}

## 参考

- [{{references[].title}}]({{references[].url}})

## 未確定事項

<!-- 静的解析では確認できない条件（メッセージ配信の保証、実行時の構成、意図された所有関係など）。 -->
- 

## 対応完了の条件

- [ ] 修正がマージされた
- [ ] 適合性チェックが修正前の構造で失敗し、修正後に成功する
- [ ] 対象フローの振る舞いが変わらないこと（positive control）を確認した
- [ ] findings.json の `status` を `Fixed` に更新した
