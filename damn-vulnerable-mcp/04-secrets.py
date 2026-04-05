# DAMN VULNERABLE MCP #04 — Hardcoded Secrets
# INTENTIONALLY VULNERABLE — security scanner test target.
# Expected: secrets_hardcoded (CRITICAL/HIGH), tls_disabled, credential_in_args
# DO NOT use in production. All keys below are FAKE test values.

from __future__ import annotations

import json

# VULN 1: Hardcoded AWS key (CRITICAL)
AWS_ACCESS_KEY = "AKIAI44QH8DHBK3R7VNK"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzRgSd4Ncv2"

# VULN 2: Hardcoded Stripe key (CRITICAL)
STRIPE_API_KEY = "sk_live_a1B2c3D4e5F6g7H8i9J0"  # noqa: not a real key

# VULN 3: Hardcoded Slack token (CRITICAL)
SLACK_BOT_TOKEN = "xoxb-7138274615-a1B2c3D4e5F6g7H8i9J0k1L2"  # noqa: not a real token

# VULN 4: Hardcoded OpenAI key (CRITICAL)
OPENAI_API_KEY = "sk-proj-abcdefghijklmnopqrstuv"

# VULN 5: Hardcoded GitHub token (CRITICAL)
GITHUB_TOKEN = "ghp_ABCDefgh1234567890abcdefghijklmnopqr"

# VULN 6: JWT token in source (HIGH)
SESSION_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# VULN 7: Connection string with password (HIGH)
DATABASE_URL = "postgresql://admin:p4ssw0rd_Pr0d@db.internal:5432/production"

# VULN 8: TLS disabled (HIGH)
import requests

resp = requests.get("https://api.internal.com/data", verify=False)

# VULN 9: Private key in source (CRITICAL)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB5mG2Dz0GjRNJSg2fg
ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstu
-----END RSA PRIVATE KEY-----"""

# VULN 10: Password in command arguments (HIGH)
import subprocess

subprocess.run(["mysql", "-u", "root", "--password=Pr0dP4ss!", "-e", "SELECT 1"])

# VULN 11: GitLab token (CRITICAL)
GITLAB_TOKEN = "glpat-ABCDefghIJKLmnopQRST"

# VULN 12: npm token (CRITICAL)
NPM_TOKEN = "npm_ABCDefghIJKLmnopQRSTuvwxyz0123456789"


def handle_request(name: str, arguments: dict) -> str:
    """Handle MCP tool calls."""
    if name == "query_db":
        return f"Query result: {arguments.get('sql', '')}"
    if name == "send_slack":
        return "Message sent"
    if name == "call_api":
        return "API called"
    return "Unknown tool"
