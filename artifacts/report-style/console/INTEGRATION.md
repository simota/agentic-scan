# console-triage 展開手順書

`console.css` と `console.js` は共通部品です。この手順書では、これを 12 スキルのレポート(`dashboard.html` と `assessment.html` / PDF)に組み込む方法を説明します。

- 実装済みのリファレンスは security-scan です。
  - `security-scan/skills/security-scan/scripts/render.py` の `console_lane()`、`console_model()`、`console_band_html()`、`console_tiles_html()`
  - `report_assets/console.{css,js}`
  - テストは `security-scan/tests/test_console_report.py`
- デザインの出典は `../03-mission-control.*` と `../10-triage-queue.*` です。
- トークンは `site/styles.css` の値を使います。

## 1. 原則

- **レーンはスキルが決める。** `console.js` は、モデルの `finding.lane` にあるキーのレーンへカードを置くだけです。振り分けは、各スキルの render.py に今ある優先度・アクションのロジック(下の表)をそのまま呼んで行います。判定基準を新しく作ってはいけません。
- **既存の出力は削らない。**
  - 指摘一覧のテーブル、フィルタ、ファセット、LLM 用コピー、優先リスト、カード、判断・制約の各節はそのまま残します。
  - 新しい層は上に足すだけです。
  - 新しいクラスにはすべて `cx-` を付けます。既存の `.card` / `.panel` / `.copy-finding` などとは衝突しません。
- **自己完結にする。** 外部リソースは使いません。`console.css` / `console.js` は各スキルの `report_assets/` にコピーし、インラインで埋め込みます。正本は `artifacts/report-style/console/` に置きます。直すときは正本を直してから、各スキルへコピーし直します。

## 2. 正規化モデル

render.py は、ダッシュボードのデータ JSON に `console` キーとして次のモデルを埋め込みます。assessment 側では、同じモデルから静的な HTML を作ります。

```jsonc
{
  "meta": {
    "skill": "security-scan",        // 帯のワードマーク横
    "title": "<project>",            // 帯の h1
    "title_id": "cx-title",
    "context": ["2026-10-06", "<commit>", "<scope>", "read-only"],  // 空要素は出さない
    "headline": "<一文の要約>"        // 任意
  },
  "counts": {"open": 4, "closed": 2, "excluded": 1, "total": 7},   // 帯の読み値
  "severities": ["High", "Medium", "Low", "Info"],                 // タイルの順
  "verdicts": [                                                    // 判定帯グラフの順
    {"key": "Valid", "label": "Valid", "tone": "strong|mid|hatch|weak", "excluded": false},
    {"key": "FalsePositive", "label": "FalsePositive", "excluded": true}   // excluded は独立したアクセント区画
  ],
  "lanes": [                                                       // 並び順 = 表示順(番号付き)
    {"key": "fix_now", "label": "FIX NOW / 修正計画", "note": "...", "tone": "high|medium|low|accent|muted|ink"}
  ],
  "perspectives": [{"name": "...", "result": "...", "note": "...", "tone": "high|...|muted", "on": true}],
  "findings": [{
    "id": "F-001", "severity": "High", "status": "Open", "status_label": "Open",
    "verdict": "Valid", "title": "...", "location": "src/a.py:42",
    "lane": "fix_now",               // lanes[].key のどれか(必須)
    "open": true,                    // タイルの塗り(未解決)
    "excluded": false,               // タイルから外す / 点線カード
    "anchor": "finding-1",           // 「一覧で開く」の #リンク先(既存の行アンカー)
    "tags": ["アプリケーション", "Confirmed"],   // カードとインスペクターのチップ
    "where": [{"label": "場所", "value": "...", "mono": true}],   // インスペクター 1: 該当箇所(空値は出さない)
    "evidence": {"text": "...", "method": "review", "notes": ["..."]},  // インスペクター 2: 根拠
    "fix": "...",                    // インスペクター 3: 修正方針
    "guidance": "..."                // 任意。レーンの行動指示
  }],
  "labels": {"severity_h": "...", "copy": "...", "lane_empty": "...", "...": "..."}  // cx_* ラベルから cx_ を除いたもの
}
```

- タイルは `excluded=false` の記録だけを数えます。1 件を 1 マスで描き、`open` のものを塗ります。
- 判定帯グラフは全記録の `verdict` を数えます。
- インスペクターの並びは、見出し → 該当箇所 → 根拠 → 修正方針で固定です。
- 画面に出す文字列はすべて `labels` から取ります。ja / en は render.py の LABELS で持ちます。

## 3. dashboard.html への組み込み

1. `report_assets/` に `console.css` と `console.js` をコピーします。読み込み関数を足します(security-scan では `report_style.console_css()` / `console_js()`)。
2. CSS は、既存の dashboard.css(とスキル固有 CSS)の **後ろ** に連結します。`console.css` は旧トークン名(`--panel --text --soft --tint --warn --warn-line --serif`)をブランドの値に付け替えます。また `--appbar-h:0` にします。
3. テンプレートを変えます。
   - 既存の appbar を、反転帯 `<header class="cx-band">` に置き換えます。中身は `data-cx="ident"`、`<dl data-cx="readout">`、`.cx-tools` です。既存の `#theme` ボタンと assessment へのリンクは `.cx-tools` に移します。
   - `<div class="cx" id="console"><div class="cx-grid">` を、`.shell` の直前に置きます。その中に次の 4 つを入れます。
     - `section.cx-p.cx-sev[data-cx=severity]`
     - `.cx-ver[data-cx=verdicts]`
     - `.cx-cov[data-cx=perspectives]`
     - `section.cx-triage#triage`(中に `.cx-board[data-cx=board]` と `aside.cx-insp[data-cx=inspector]`)
   - 指摘一覧(フィルタとテーブル)の節は、`<main>` の先頭に移します。
   - 既存の h1(プロジェクト名)は帯へ移します。ページの h1 は 1 つにします。
   - ナビには `#triage` を足します。
4. JS: `console.js` は、既存のページスクリプトと **同じ `<script>` 要素の先頭** に入れます。スクリプトの数はテストで固定されているものが多いためです。既存の IIFE の最後で、次のように呼びます。

   ```js
   window.AgenticConsole.mount(D.console, {root: document,
     copy: function (card) { return copyText(findingMarkdown(findById(card.id))); }});
   ```

   - コピーは既存の LLM 用 Markdown 関数を再利用します。
   - ボタンのラベルは `cx_copy` を使い、既存の `copy_llm` とは別の名前にします。同じ名前だと、`get_by_role(name=...)` を使う既存テストが 2 件にヒットしてしまいます。
5. ライト / ダークは、既存の `data-theme` 切り替えのままで動きます。`console.css` の dark ブロックは `:root:not([data-theme=light]):not(.cx-doc)` と `:root[data-theme=dark]:not(.cx-doc)` に当たります。
6. 印刷時は次のようになります(`@media print`): ライト値に固定、レーンは縦 1 列、インスペクターはレーンの後ろに static で出る、ツールとコピーボタンは隠す。

## 4. assessment.html / PDF への組み込み

1. `<html class="cx-doc">` を付けます。これで dark トークンが効かなくなり、紙として常にライトになります。CSS は document.css(とスキル固有 CSS)の後ろに `console.css` を連結します。
2. `<body>` の先頭に `console_band_html(cm, <レポート種別名>)` を置きます。既存の report-header からは h1 / project を外し、kicker とメタ行は残します。その直後に `console_tiles_html(cm)` を置きます。どちらも script を使わない静的な HTML です。
3. 優先キューは、同じ 4 レーンの順で縦に並べます。
   - 未対応のレーン(security-scan では FIX NOW / VERIFY FIRST)は `#priority-queue` の中に入れます。各レーンの中で、既存の part 別テーブルを使います。見出し id は `priority-queue-<lane>-<part>` です。
   - CLOSED / EXCLUDED は、その直後の `#closed-lanes` に、アンカー付きの簡易リストで並べます。
   - レーン要素の id は `lane-<key>` です。
   - `#priority-queue` には未対応の項目だけを残します。既存テストの「Fixed が優先キューに出ない」「closed しかない場合はリンク 0」を保つためです。
4. PDF は、帯とタイルを `print-color-adjust: exact` で反転したまま出します。注意: 種別名の `.cx-kind` に `text-transform: uppercase` を付けると、PDF のテキスト抽出が大文字になります。security-scan の PDF テストはこれで落ちたので付けていません。

## 5. スキル別: レーン名と振り分け元

調査時点(2026-11-19)の各スキルの render.py に基づいています。行番号は調べた時点のものです。

| スキル | 振り分け元(既存ロジック) | 未対応レーン(キー → 表示名 en / ja) | CLOSED / EXCLUDED の元 | コピー関数 | 観点との紐付け |
|---|---|---|---|---|---|
| security-scan(適用済) | `action_kind()` を `report_model()["queue"]` 経由で使う | `fix_now` FIX NOW / 修正計画、`verify_first` VERIFY FIRST / 先に検証 | `status in (Fixed, Accepted)` / `verdict in EXCLUDED` | JS `findingMarkdown` | `category == perspective.name`(ランプ用) |
| architecture-scan | `action(f)` render.py:952(Valid かつ Confirmed なら fix_now)。キューは `html_priority` :1489 で Open かつ除外以外 | `fix_now` Plan the fix / 修正を計画、`verify_first` Verify first / 先に検証する | `STATUSES` findings.py:92、`is_excluded()` :948 | Py `finding_markdown` :973 → `copy-data` | `category`(PERSPECTIVES で検証、findings.py:284) |
| bug-scan(`scan_report_kit/assets`) | fix_now / verify_first の区別はない。`common_finding()` :67 は、修正方針があって `closed()` でなければ `action={label:"Fix direction"}` を付ける。キット側の並びは (status≠Open, severity) | **未決**: 「修正方針あり / なし」で 2 レーンにするか、1 レーン(OPEN)にするか | `KIT_STATUS` :51(Fixed/Verified→Fixed、Accepted→Accepted)、`common.excluded()` | キット `findingMarkdown`(dashboard.js:224) | `finding.pattern` → 観点名 `<pattern> <name>` |
| data-integrity-scan | `action(f)` :692 | `fix_now` Ready to ship / すぐ適用できる、`pin_first` Stage the rollout / 段階的に適用する、`verify_first` Verify first / 先に検証する | STATUSES findings.py:91、`is_excluded` :689 | Py `finding_markdown` :714 | `category` |
| infra-security-scan | アクション関数も優先キューもない。並びは `ordered()` :762(重大度、id の順) | **未決**: findings に status がないため、CLOSED は常に空。F-*(レビュー) / I-*(ベースライン)と `covered_by()` :768 はあるが、行動の区分ではない | status なし / `EXCLUDED` :51 | Py `finding_markdown` :846 → `#md` | `category` = 観点名 |
| logic-scan | `action(f)` :700 | `fix_now` Ready to fix / すぐ直せる、`pin_first` Coordinate the change / 影響先と合意して直す、`verify_first` Verify first / 先に検証する | STATUSES findings.py:91、`is_excluded` :697 | Py `finding_markdown` :722 | `category` |
| performance-scan | アクション関数なし。`finding_group()` :171 は excluded か重大度を返すだけ | **未決**(行動の区分がない) | STATUSES findings.py:59 / `is_excluded` :167 | Py `llm_finding` :652 → `data-llm` | `category` |
| privacy-scan | アクション関数なし。重大度と excluded だけ | **未決**(行動の区分がない) | STATUSES findings.py:77 / `findings.excluded()` :716 | **なし**(インスペクターのコピーは出さない) | `category`(PERSPECTIVES で検証) |
| prompt-scan | `dashboard_model()` 内の `action(f)` :713。JS 側にも同じ判定(:470) | `fix_now` / `verify_first`(ラベルは security と同じ)。`kind` ∈ {defect, improvement} はタグとして付ける | record.py の STATUSES :18 / EXCLUDED :20 | JS `findingMarkdown` :506 | 紐付けなし(`category` は自由記述) |
| prune-scan | `act_now(f)` :287 と `subtraction_groups()` :294 | `now` 引き算 - 今すぐ削除、`reduce` 縮小・統合、`decide` 人が判断(いずれも既存ラベル :81 / :113)。**注意**: `Unlikely` は既存ロジックでどのグループにも入らない | STATUSES findings.py:41 / EXCLUDED :43 | キット `findingMarkdown` | `perspective`(手順 ID)。名前では結び付かない |
| test-gap-scan | `action(f)` :688 | `fix_now` Ready to write / すぐ書ける、`pin_first` Change production code first / 先に本番コードを整える、`verify_first` Verify first / 先に検証する | STATUSES findings.py:89、`is_excluded` :685 | Py `finding_markdown` :710 | `category` |
| ux-scan | `to_common()` :311(Open かつ Valid かつ修正方針あり → Fix、それ以外の Open → Verify first。confidence は見ない) | `fix` Fix / 修正、`verify` Verify first / 先に検証 | STATUSES findings.py:43 / EXCLUDED :45 | キット `findingMarkdown` | `perspective`(手順 ID) |

- `pin_first` を持つ 3 スキル(data-integrity / logic / test-gap)は、未対応のレーンが 3 本になります。そのため全体は 5 レーンです。`console.js` はレーン数に依存しません。ただし `.cx-board` は 2 列なので、5 本目は 3 段目に 1 本だけ並びます。
- prune-scan で `Unlikely` を扱うには、既存の規則にない置き場所が要ります。
- 観点ランプの紐付け方は、スキルごとに `perspectives[].tone/on` を render.py 側で決めます。紐付けがないスキル(prompt / prune / ux)では、すべて `muted`・消灯にするのが無難です。

## 6. テストの注意点

- **スクリプト数**: security-scan と ux-scan はダッシュボードの `<script>` を 2 本と固定しています。`console.js` は既存のスクリプトに連結してください。
- **CSP**: privacy-scan は `<meta http-equiv=Content-Security-Policy>` に、唯一の `<script>` と `<style>` の sha256 を入れています(render.py:640 / :686)。連結した後の本文でハッシュを計算してください。
- **テンプレート固定**: ux-scan の `tests/test_page_shell.py` は、テンプレートが変わると落ちます。意図した変更として更新が必要です。
- **ナビと id**: 次のテストは、appbar / sidebar / ナビのリンク先 / ファセット数を検証しています。帯への置き換えや `#triage` の追加に合わせて更新が必要です。
  - architecture-scan: `test_dashboard_quality.py`(`header.appbar`、`nav.sidebar`)
  - infra-security-scan: `test_report_views.py`(`header.appbar`、`masthead` がないこと)
  - performance-scan: `test_render_layout.py`
  - data-integrity / logic / test-gap: ナビのリンク一覧を完全一致で比べています(例: `test_data_scan.py:1539`)
- **優先キューの件数と並び**: `priority-item` の件数 4 / 12(data-integrity / logic / test-gap)と、security-scan の `#priority-queue` 内の並び順のテストがあります。既存の優先リストは削らずに残せば、件数のテストはそのまま通ります。assessment をレーン順にすると並び順のテストは変わるので、レーン順として書き直します(security-scan の `test_priority_is_severity_first_then_readiness_then_id` を参照)。
- **`.innerHTML` の禁止**: security-scan のテストにあります。`console.js` は DOM API だけで書いてあるので、他スキルでもそのまま通ります。
- **コピーボタンの名前**: インスペクターのコピーは `cx_copy` ラベルにします。既存の `copy_llm` と同じ名前にすると、`get_by_role("button", name=..., exact=True)` を使うテストが 2 件にヒットします。
- **ブラウザテスト**: security-scan のブラウザテストは `SECURITY_SCAN_BROWSER_TEST=1 CHROME=<chrome-headless-shell>` で opt-in です。macOS のサンドボックス内では Chrome の Mach ポート登録が拒否されるので、サンドボックスの外で実行します。
- **追加すべきテスト**(security-scan の `test_console_report.py` の構成を参照):
  - 振り分けの検証: 全記録の lane が、既存の関数の結果と除外・終了の規則とに一致すること
  - モデルが埋め込まれ、スロットがそろっていること
  - assessment の帯の読み値、タイルのマス、レーン順
  - opt-in のブラウザテスト: カード選択 → インスペクターの順 → コピー、360px で横スクロールがないこと
