"""Packages and modules that frameworks load by name, and client calls, are not removal candidates."""

import json
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


def routes(result):
    return {row["route"] for row in result["routes"]}


class NamespaceImportTests(unittest.TestCase):
    def test_names_imported_from_a_namespace_package_match_its_distribution(self):
        result = scan({
            "requirements.txt": "google-cloud-bigquery==3.25.0\ngoogle-cloud-firestore\nazure-storage-blob\n"
                                "google-cloud-pubsub\n",
            "main.py": "from google.cloud import bigquery, firestore\nfrom azure.storage import blob\n",
        })
        self.assertEqual(unimported(result), {"google-cloud-pubsub": "unreferenced"})

    def test_prefixed_distributions_match_their_import_name(self):
        result = scan({
            "requirements.txt": "python-decouple\npython-slugify\ndjango-environ\npython-unused\n",
            "main.py": "from decouple import config\nfrom slugify import slugify\nimport environ\n",
        })
        self.assertEqual(unimported(result), {"python-unused": "unreferenced"})


class DjangoSettingsTests(unittest.TestCase):
    def test_installed_apps_and_middleware_load_their_packages(self):
        result = scan({
            "requirements.txt": "django-cors-headers==4.3\nwhitenoise\ndjango-debug-toolbar\n",
            "mysite/settings.py": 'INSTALLED_APPS = [\n    "django.contrib.admin",\n    "corsheaders",\n]\n'
                                  'MIDDLEWARE = [\n    "corsheaders.middleware.CorsMiddleware",\n'
                                  '    "whitenoise.middleware.WhiteNoiseMiddleware",\n]\n',
        })
        self.assertEqual(unimported(result), {"django-debug-toolbar": "unreferenced"})

    def test_strings_outside_settings_load_no_package(self):
        result = scan({
            "requirements.txt": "whitenoise\n",
            "main.py": 'NAME = "whitenoise"\n',
        })
        self.assertEqual(unimported(result), {"whitenoise": "unreferenced"})


class ServerModuleTests(unittest.TestCase):
    def test_server_commands_name_single_modules_and_factories(self):
        result = scan({
            "hello.py": "def create_app():\n    return None\n",
            "service.py": "app = object()\n",
            "factory.py": "def make():\n    return None\n",
            "unused.py": "A = 1\n",
            "Procfile": "web: gunicorn -w 4 'hello:create_app()'\n",
            "Dockerfile": 'CMD ["uvicorn", "service:app", "--host", "0.0.0.0"]\n',
            "deploy.yml": 'command: "gunicorn \'pkg.factory:make()\'"\n',
            "pkg/__init__.py": "",
            "pkg/factory.py": "def make():\n    return None\n",
        })
        found = orphans(result)
        self.assertFalse({"hello.py", "service.py", "pkg/factory.py"} & found, found)
        self.assertIn("unused.py", found)

    def test_container_tags_name_no_module(self):
        result = scan({
            "redis.py": "A = 1\n",
            "compose.yml": 'services:\n  cache:\n    image: "redis:alpine"\n',
            "Dockerfile": "FROM redis:alpine\n",
        })
        self.assertIn("redis.py", orphans(result))


class HttpClientRouteTests(unittest.TestCase):
    def test_calls_on_an_imported_or_typed_client_instance_are_not_routes(self):
        result = scan({
            "src/lib/api.ts": "import axios from 'axios';\nconst api = axios.create({ baseURL: '/api' });\n"
                              "export default api;\n",
            "src/pages/Orders.tsx": "import api from '../lib/api';\nexport async function load() {\n"
                                    "  await api.get('/orders');\n  await api.post('/orders/refund', {});\n}\n",
            "src/client.ts": "import axios, { AxiosInstance } from 'axios';\n"
                             "export const api: AxiosInstance = axios.create({});\n"
                             "export const me = () => api.get('/users/me');\n",
            "package.json": json.dumps({"dependencies": {"axios": "1"}}),
        })
        self.assertEqual(routes(result), set())

    def test_an_express_router_named_api_still_defines_routes(self):
        result = scan({
            "server/api.js": "const express = require('express');\nconst api = express.Router();\n"
                             "api.get('/health', (req, res) => res.send('ok'));\nmodule.exports = api;\n",
            "server/extra.js": "const api = require('./api');\napi.post('/items', (req, res) => res.end());\n",
            "package.json": json.dumps({"dependencies": {"express": "4"}}),
        })
        self.assertEqual(routes(result), {"/health", "/items"})


class PackageConfigTests(unittest.TestCase):
    def test_packages_named_in_package_json_configuration_are_script_only(self):
        result = scan({
            "package.json": json.dumps({
                "scripts": {"test": "jest"},
                "devDependencies": {"jest": "29", "ts-jest": "29", "identity-obj-proxy": "3",
                                    "@acme/prettier-config": "1", "commitizen": "4",
                                    "cz-conventional-changelog": "3", "left-pad": "1"},
                "jest": {"preset": "ts-jest", "moduleNameMapper": {"\\.css$": "identity-obj-proxy"}},
                "prettier": "@acme/prettier-config",
                "config": {"commitizen": {"path": "cz-conventional-changelog"}},
            }, indent=2),
        })
        statuses = unimported(result)
        self.assertEqual(statuses.pop("left-pad"), "unreferenced")
        self.assertEqual(set(statuses.values()), {"script_only"}, statuses)

    def test_pyproject_tool_tables_name_their_tools(self):
        result = scan({
            "pyproject.toml": '[project]\nname = "x"\ndependencies = ["uvicorn", "httpie"]\n\n'
                              '[tool.poe.tasks]\nserve = "uvicorn main:app --reload"\n',
            "main.py": "app = None\n",
        })
        self.assertEqual(unimported(result), {"uvicorn": "script_only", "httpie": "unreferenced"})


class MakefileTargetTests(unittest.TestCase):
    def test_target_specific_variables_add_no_second_target(self):
        result = scan({
            "Makefile": "build:\n\tgo build ./...\nrelease: GOOS=linux\nrelease: export CGO_ENABLED=0\n"
                        "release: build\n\t./release.sh\n",
        })
        rows = [(row["name"], row["location"]) for row in result["scripts"]]
        self.assertEqual(rows, [("build", "Makefile:1"), ("release", "Makefile:5")])


if __name__ == "__main__":
    unittest.main()
