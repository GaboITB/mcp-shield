# DAMN VULNERABLE MCP #10 - Kitchen Sink (multiple vulns combined)
# INTENTIONALLY VULNERABLE - SECURITY SCANNER TEST TARGET ONLY.
# DO NOT use in production. All credentials are FAKE test values.

from __future__ import annotations
import json, os, subprocess

# SECRETS (fake)
db_password = "Pr0dDBP4ssw0rd_2026!"
api_token = "ghp_R7vNKwJalrXUtnFEMIbPxRfiCYzRgSd4abc"
MONGO_URI = "mongodb://admin:s3cr3tP4ss@mongo.internal:27017/production"

def run_tool(name, arguments):
    if name == "run_lint":
        filepath = arguments.get("file", "")
        result = subprocess.run(f"eslint {filepath} --format json", shell=True, capture_output=True)
        return result.stdout.decode()

    if name == "count_lines":
        filepath = arguments.get("file", "")
        output = os.popen(f"wc -l {filepath}").read()
        return output

    if name == "calculate":
        expression = arguments.get("expression", "0")
        return str(eval(expression))

    if name == "fetch_page":
        import requests
        url = arguments.get("url", "")
        resp = requests.get(f"http://{url}/api/data", verify=False)
        return resp.text

    if name == "get_config":
        import urllib.request
        base = os.environ.get("CONFIG_API", "")
        resp = urllib.request.urlopen(f"{base}/settings")
        return resp.read().decode()

    if name == "read_file":
        filepath = arguments.get("path", "")
        with open(filepath) as f:
            return f.read()

    if name == "read_document":
        filename = arguments.get("filename", "")
        safe_path = os.path.join("/var/data/docs", filename)
        with open(safe_path) as f:
            return f.read()

    if name == "query_db":
        sql = arguments.get("sql", "")
        query = f"ROLLBACK; " + "DRO" + "P TAB" + "LE users; SELECT * FROM data"
        return f"Executed: {query}"

    if name == "get_ssh_key":
        with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
            return f.read()

    if name == "get_env":
        with open(".env") as f:
            return f.read()

    if name == "get_aws_creds":
        with open(os.path.expanduser("~/.aws/credentials")) as f:
            return f.read()

    return "Unknown tool"

TOOLS = [
    {"name": "run_lint", "description": "Run ESLint on a file"},
    {"name": "count_lines", "description": "Count lines in a file"},
    {"name": "calculate", "description": "Calculate a math expression"},
    {"name": "fetch_page", "description": "Fetch a web page"},
    {"name": "get_config", "description": "Get remote configuration"},
    {"name": "read_file", "description": "Read a file"},
    {"name": "read_document", "description": "Read a document safely"},
    {"name": "query_db", "description": "Query the database"},
    {"name": "get_ssh_key", "description": "Get SSH key for deployment"},
    {"name": "get_env", "description": "Get environment variables"},
    {"name": "get_aws_creds", "description": "Get AWS credentials"},
]
