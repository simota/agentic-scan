"""Files a declared framework loads by location, its named exports and its JSX runtime are not candidates."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "prune-scan" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from test_deep_review_fixes import scan  # noqa: E402


def unimported(result):
    return {row["name"]: row["status"] for row in result["unimported_dependencies"]}


def orphans(result):
    return {row["path"] for row in result["orphan_files"]}


def symbols(result):
    return {row["name"] for row in result["unreferenced_symbols"]}


NEXT_APP = {
    "package.json": '{"scripts": {"dev": "next dev"}, "dependencies": {"next": "14", "react": "18", '
                    '"react-dom": "18", "lodash": "4"}}',
    "app/layout.tsx": "export const metadata = { title: 'x' }\n"
                      "export default function RootLayout({ children }) { return <html>{children}</html> }\n",
    "app/page.tsx": "import Card from '../components/Card'\nexport default function Page() { return <Card /> }\n",
    "app/about/page.tsx": "export async function generateStaticParams() { return [] }\n"
                          "export const unusedHelper = 1\n"
                          "export default function About() { return <p>about</p> }\n",
    "app/about/stale.ts": "export const stale = 1\n",
    "app/api/hello/route.ts": "export async function GET() { return Response.json({}) }\n",
    "components/Card.tsx": "export default function Card() { return <div /> }\n",
    "components/Old.tsx": "export default function Old() { return <div /> }\n",
    "pages/legacy.tsx": "export async function getServerSideProps() { return { props: {} } }\n"
                        "export default function Legacy() { return <p /> }\n",
    "src/middleware.ts": "export function middleware() {}\nexport const config = { matcher: '/about' }\n",
}


class NextConventionTests(unittest.TestCase):
    def test_files_next_loads_by_location_are_not_orphans(self):
        self.assertEqual(orphans(scan(NEXT_APP)), {"app/about/stale.ts", "components/Old.tsx"})

    def test_exports_next_reads_by_name_are_not_unreferenced(self):
        self.assertEqual(symbols(scan(NEXT_APP)), {"unusedHelper", "stale"})

    def test_next_needs_react_and_react_dom_without_an_import(self):
        self.assertEqual(unimported(scan(NEXT_APP)), {"next": "script_only", "lodash": "unreferenced"})

    def test_conventions_apply_only_where_the_framework_is_declared(self):
        files = {k.replace("app/", "apps/web/app/", 1) if k.startswith("app/") else k: v
                 for k, v in NEXT_APP.items() if k != "package.json"}
        files["package.json"] = '{"dependencies": {"react": "18"}}'
        files["apps/web/package.json"] = '{"dependencies": {"next": "14"}}'
        files["apps/admin/page.tsx"] = "export default function Page() { return <p /> }\n"
        found = orphans(scan(files))
        self.assertNotIn("apps/web/app/page.tsx", found)
        self.assertIn("apps/admin/page.tsx", found)
        self.assertIn("pages/legacy.tsx", found)  # The root manifest declares no Next.js.

    def test_another_frameworks_export_names_stay_unreferenced(self):
        files = dict(NEXT_APP)
        files["pages/legacy.tsx"] += "export const load = () => 42\nexport function loader() {}\n"
        self.assertEqual(symbols(scan(files)), {"unusedHelper", "stale", "load", "loader"})

    def test_a_page_file_without_the_framework_is_still_judged(self):
        result = scan({
            "package.json": '{"dependencies": {"react": "18"}}',
            "app/page.tsx": "export function GET() {}\nexport default function Page() { return <p /> }\n",
        })
        self.assertEqual(orphans(result), {"app/page.tsx"})
        self.assertEqual(symbols(result), {"GET"})


class OtherFrameworkTests(unittest.TestCase):
    def test_sveltekit_routes_hooks_and_their_exports(self):
        result = scan({
            "package.json": '{"devDependencies": {"@sveltejs/kit": "2"}}',
            "src/routes/+page.ts": "export async function load() { return {} }\nexport const prerender = true\n",
            "src/routes/blog/+page.server.ts": "export const actions = {}\n",
            "src/routes/api/+server.ts": "export function GET() {}\n",
            "src/hooks.server.ts": "export async function handle({ event, resolve }) { return resolve(event) }\n",
            "src/lib/unused.ts": "export const unused = 1\n",
        })
        self.assertEqual(orphans(result), {"src/lib/unused.ts"})
        self.assertEqual(symbols(result), {"unused"})

    def test_remix_routes_and_loaders(self):
        result = scan({
            "package.json": '{"dependencies": {"@remix-run/react": "2", "react": "18", "react-dom": "18"}}',
            "app/root.tsx": "import { Outlet } from '@remix-run/react'\nexport function links() { return [] }\n"
                            "export default function App() { return <Outlet /> }\n",
            "app/routes/_index.tsx": "export async function loader() { return null }\n"
                                     "export default function Index() { return <p /> }\n",
        })
        self.assertEqual(orphans(result), set())
        self.assertEqual(symbols(result), set())
        self.assertEqual(unimported(result), {})

    def test_nuxt_pages_and_server_routes(self):
        result = scan({
            "package.json": '{"dependencies": {"nuxt": "3"}}',
            "pages/about.vue": "<template><p /></template>\n",
            "server/api/hello.ts": "export default defineEventHandler(() => 'hi')\n",
            "utils/stale.ts": "export default 1\n",
        })
        self.assertEqual(orphans(result), {"utils/stale.ts"})


class JsxRuntimeTests(unittest.TestCase):
    def test_jsx_files_import_react_through_the_automatic_runtime(self):
        result = scan({
            "package.json": '{"dependencies": {"react": "18", "react-dom": "18"}}',
            "src/index.tsx": "import { createRoot } from 'react-dom/client'\n"
                             "createRoot(document.body).render(<p />)\n",
        })
        self.assertEqual(unimported(result), {})

    def test_jsx_import_source_names_the_runtime_package(self):
        result = scan({
            "package.json": '{"dependencies": {"react": "18", "preact": "10", "@emotion/react": "11"}}',
            "tsconfig.json": '{"compilerOptions": {"jsx": "react-jsx", "jsxImportSource": "preact"}}',
            "src/index.tsx": "export default function A() { return <p /> }\n",
            "src/styled.tsx": "/** @jsxImportSource @emotion/react */\nexport const B = () => <p />\nB()\n",
        })
        self.assertEqual(unimported(result), {"react": "unreferenced"})

    def test_an_unused_sibling_config_does_not_choose_the_runtime(self):
        result = scan({
            "package.json": '{"dependencies": {"react": "18", "preact": "10"}}',
            "tsconfig.json": '{"compilerOptions": {"jsx": "react-jsx"}}',
            "tsconfig.unused.json": '{"compilerOptions": {"jsxImportSource": "preact"}}',
            "src/index.tsx": "export default function A() { return <p /> }\n",
        })
        self.assertEqual(unimported(result), {"preact": "unreferenced"})

    def test_a_nearer_config_without_the_field_keeps_react(self):
        result = scan({
            "package.json": '{"dependencies": {"react": "18", "preact": "10"}}',
            "tsconfig.json": '{"compilerOptions": {"jsxImportSource": "preact"}}',
            "web/tsconfig.json": '{"compilerOptions": {"jsx": "react-jsx"}}',
            "web/index.tsx": "export default function A() { return <p /> }\n",
        })
        self.assertEqual(unimported(result), {"preact": "unreferenced"})

    def test_extended_and_referenced_configs_set_the_runtime(self):
        result = scan({
            "package.json": '{"dependencies": {"react": "18", "preact": "10", "solid-js": "1"}}',
            "tsconfig.json": '{"files": [], "references": [{"path": "./tsconfig.app.json"}]}',
            "tsconfig.app.json": '{\n  // JSONC comments are allowed\n  "extends": "./tsconfig.base.json"\n}',
            "tsconfig.base.json": '{"compilerOptions": {"jsxImportSource": "preact"}}',
            "src/index.tsx": "export default function A() { return <p /> }\n",
            "solid/tsconfig.json": '{"extends": ["../tsconfig.base.json", "./tsconfig.solid.json"]}',
            "solid/tsconfig.solid.json": '{"compilerOptions": {"jsxImportSource": "solid-js"}}',
            "solid/App.tsx": "export default function B() { return <p /> }\n",
        })
        self.assertEqual(unimported(result), {"react": "unreferenced"})

    def test_without_jsx_files_react_stays_a_candidate(self):
        result = scan({
            "package.json": '{"dependencies": {"react": "18"}}',
            "src/index.ts": "export const x = 1\n",
        })
        self.assertEqual(unimported(result), {"react": "unreferenced"})


if __name__ == "__main__":
    unittest.main()
