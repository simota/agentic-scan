<!--
1 件の finding を 1 件の issue として登録するテンプレート（1 根本原因 = 1 修正箇所 = 1 issue）。
各欄の {{field}} は findings.json の同名フィールドから転記する。空の任意欄は行ごと削除する。

登録前に確認すること:
- 未修正の High / Medium を公開リポジトリの公開 issue に書かない。非公開トラッカーか Security Advisory を使う
- アカウント ID、プロジェクト ID、バケット名、IP アドレスなど環境を特定できる値は、issue の閲覧範囲に合わせて伏せる
- シークレットの値を書かない。場所と種類だけを書く
- 権限昇格や侵入の具体的な手順・スクリプトを書かない。経路は権限名とリソースアドレスで示す
-->

**タイトル:** [{{severity}}] {{title}} ({{id}})

## 概要

| 項目 | 値 |
|---|---|
| ID | {{id}} |
| 深刻度 / 確度 | {{severity}} / {{confidence}} |
| 検証判定 | {{validation.verdict}} |
| 観点 | {{category}} |
| プロバイダー | {{provider}} |
| リソース | `{{resources}}` |
| 場所 | `{{location}}` |
| 攻撃経路 | {{attack_paths}} |
| ベンチマーク / CWE | {{controls}} / {{cwe}} |
| 対象リビジョン | {{meta.commit}} |
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

## 何が起きるか

{{impact}}

## 攻撃経路（静的）

**起点となる主体:** {{actor}}

**経路（各段の根拠 `path:line`）:**

{{path}}

**対照（正しく設定されている同種リソース）:** {{contrast}}

<!-- Environment-dependent の場合、前提となる設定（{{condition}}）をここに書く。 -->

## 根拠

{{validation.evidence}}

## 修正方針

{{fix}}

- **回帰を防ぐポリシー（policy as code）:** {{regression}}

## 参考

- [{{references[].title}}]({{references[].url}})

## 未確定事項

<!-- 構成ファイルからは確認できない条件（SCP / 組織ポリシー、手動変更、変数の実値など）。 -->
- 

## 対応完了の条件

- [ ] IaC の修正がマージされ、適用された
- [ ] 回帰を防ぐポリシーが CI に追加された
- [ ] 適用後の設定（plan またはスナップショット）で、経路が遮断されていることを確認した
