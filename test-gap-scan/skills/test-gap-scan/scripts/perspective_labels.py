"""Display labels for test-gap perspectives."""

PERSPECTIVE_NAMES_JA = {
    "Untested critical paths": "重要フローの未テスト箇所",
    "Error and edge cases": "異常系と境界値",
    "Assertion strength": "アサーションの十分性",
    "Mock fidelity": "モックの再現性",
    "Nondeterminism and flakiness": "非決定性とテストの不安定さ",
    "Isolation and shared state": "テストの独立性と共有状態",
    "Integration and contract seams": "システム連携と契約の境界",
    "Test level balance": "テストレベルのバランス",
    "Regression pinning": "修正済み不具合の回帰テスト",
    "Test data and fixtures": "テストデータとフィクスチャ",
    "Disabled and skipped tests": "無効化・スキップされたテスト",
    "Suite execution in CI": "CI でのテストスイート実行",
}
PERSPECTIVE_STATUSES_JA = {"applied": "適用", "not checked": "未確認", "N/A": "該当なし"}


def perspective_name(name, lang):
    return PERSPECTIVE_NAMES_JA.get(name, name) if lang == "ja" else name


def perspective_status(status, lang):
    return PERSPECTIVE_STATUSES_JA.get(status, status) if lang == "ja" else status
