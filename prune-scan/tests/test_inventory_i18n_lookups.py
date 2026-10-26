"""Locale keys reached through plural and context suffixes or a scoped translator are not unreferenced."""

import json
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from test_deep_review_fixes import scan  # noqa: E402


def unreferenced(result):
    return {row["key"] for row in result["i18n_unreferenced"]}


BUNDLE = {
    "cart": {"item_one": "{{count}} item", "item_other": "{{count}} items", "unused_one": "x", "unused_other": "y"},
    "inbox": {"message": "message", "message_plural": "messages"},
    "friend_male": "boyfriend", "friend_female": "girlfriend",
    "page_title": "Title",
    "auth": {"login": "Log in", "logout": "Log out", "signup": "Sign up"},
}


class I18nLookupTests(unittest.TestCase):
    def test_plural_context_and_key_prefix_lookups_name_their_keys(self):
        result = scan({
            "public/locales/en/translation.json": json.dumps(BUNDLE),
            "public/locales/fr/translation.json": json.dumps(BUNDLE),
            "src/Cart.tsx": (
                "const { t } = useTranslation();\n"
                "const { t: ta } = useTranslation('translation', { keyPrefix: 'auth' });\n"
                "t('cart.item', { count: n }); t('inbox.message', { count: n });\n"
                "t('friend', { context: gender }); ta('login'); t('auth.logout'); t('page');\n"
                "const config = { context: __dirname };\n"
            ),
        })
        self.assertEqual(unreferenced(result), {"cart.unused_one", "cart.unused_other", "page_title", "auth.signup"})

    def test_next_intl_namespaces_scope_their_keys(self):
        messages = {"HomePage": {"title": "Hello", "about": "About", "stale": "Old"}, "Nav": {"home": "Home"}}
        result = scan({
            "messages/en.json": json.dumps(messages),
            "messages/de.json": json.dumps(messages),
            "app/page.tsx": "const t = useTranslations('HomePage');\nt('title'); t('about');\n",
            "app/server.tsx": "const t = await getTranslations({ locale, namespace: 'Nav' });\nt('home');\n",
        })
        self.assertEqual(unreferenced(result), {"HomePage.stale"})

    def test_many_scopes_and_literals_stay_bounded(self):
        scopes = "".join(f"useTranslations('NS{i}');\n" for i in range(2000))
        literals = "".join(f"t('k{i}');\n" for i in range(2000))
        start = time.monotonic()
        result = scan({
            "messages/en.json": json.dumps({"NS1": {"k1": "a"}, "Other": {"k1": "b"}}),
            "app/page.tsx": scopes + literals,
        })
        self.assertLess(time.monotonic() - start, 10)
        self.assertEqual(unreferenced(result), {"Other.k1"})
        self.assertEqual(result["i18n_dynamic_prefixes"], [])


if __name__ == "__main__":
    unittest.main()
