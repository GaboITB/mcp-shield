"""Typosquatting detection for npm/pip dependencies.

Compares dependency names against the top 300 popular packages using
Levenshtein distance and common confusion patterns (homoglyphs, dashes).
Zero external dependencies — uses stdlib only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_shield.core.models import Finding, Severity, Surface

# Top popular npm packages (targets for typosquatting)
_TOP_NPM = {
    "express",
    "react",
    "lodash",
    "axios",
    "chalk",
    "commander",
    "webpack",
    "typescript",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "moment",
    "debug",
    "uuid",
    "dotenv",
    "cors",
    "body-parser",
    "mongoose",
    "jsonwebtoken",
    "bcrypt",
    "passport",
    "socket.io",
    "redis",
    "pg",
    "mysql",
    "mysql2",
    "sequelize",
    "prisma",
    "next",
    "nuxt",
    "vue",
    "angular",
    "svelte",
    "fastify",
    "koa",
    "hapi",
    "yargs",
    "inquirer",
    "ora",
    "glob",
    "minimatch",
    "semver",
    "rimraf",
    "mkdirp",
    "fs-extra",
    "cross-env",
    "concurrently",
    "nodemon",
    "ts-node",
    "tsx",
    "esbuild",
    "rollup",
    "vite",
    "turbo",
    "lerna",
    "nx",
    "pnpm",
    "puppeteer",
    "playwright",
    "cheerio",
    "jsdom",
    "node-fetch",
    "undici",
    "got",
    "superagent",
    "request",
    "http-proxy",
    "express-validator",
    "helmet",
    "morgan",
    "compression",
    "cookie-parser",
    "multer",
    "sharp",
    "jimp",
    "canvas",
    "openai",
    "langchain",
    "anthropic",
    "cohere",
    "zod",
    "joi",
    "yup",
    "ajv",
    "class-validator",
    "dayjs",
    "luxon",
    "date-fns",
    "ramda",
    "immer",
    "rxjs",
    "async",
    "bluebird",
    "p-limit",
    "p-queue",
    "winston",
    "pino",
    "bunyan",
    "log4js",
    "aws-sdk",
    "firebase",
    "supabase",
    "stripe",
    "colors",
    "picocolors",
    "nanoid",
    "cuid",
    "short-uuid",
}

# Top popular PyPI packages
_TOP_PIP = {
    "requests",
    "flask",
    "django",
    "fastapi",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "pillow",
    "beautifulsoup4",
    "scrapy",
    "selenium",
    "pytest",
    "black",
    "mypy",
    "pylint",
    "ruff",
    "sqlalchemy",
    "psycopg2",
    "pymongo",
    "redis",
    "celery",
    "boto3",
    "google-cloud-storage",
    "azure-storage-blob",
    "pydantic",
    "httpx",
    "aiohttp",
    "uvicorn",
    "gunicorn",
    "cryptography",
    "paramiko",
    "fabric",
    "ansible",
    "openai",
    "anthropic",
    "langchain",
    "transformers",
    "torch",
    "tensorflow",
    "keras",
    "scikit-learn",
    "click",
    "typer",
    "rich",
    "tqdm",
    "colorama",
}

_ALL_POPULAR = _TOP_NPM | _TOP_PIP


def _levenshtein(s1: str, s2: str) -> int:
    """Levenshtein distance -- O(min(m,n)) space."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def check_typosquat(deps: dict[str, str]) -> list[Finding]:
    """Check dependency names for potential typosquatting.

    Args:
        deps: Dict of {dep_name: version_spec}.

    Returns:
        List of findings for suspected typosquats.
    """
    findings: list[Finding] = []

    for dep_name in deps:
        dep_lower = dep_name.lower().lstrip("@").replace("/", "-")

        # Skip if it IS a popular package
        if dep_lower in _ALL_POPULAR:
            continue
        # Skip scoped official packages
        if dep_name.startswith("@") and any(
            dep_name.startswith(f"@{scope}/")
            for scope in (
                "modelcontextprotocol",
                "anthropic",
                "types",
                "babel",
                "eslint",
                "jest",
                "testing-library",
            )
        ):
            continue

        suspects: list[str] = []

        for popular in _ALL_POPULAR:
            if len(dep_lower) < 4 or len(popular) < 4:
                continue

            # Levenshtein distance 1-2
            dist = _levenshtein(dep_lower, popular)
            if dist == 1:
                suspects.append(f"'{dep_name}' is 1 edit away from '{popular}'")
            elif dist == 2 and len(dep_lower) > 6:
                suspects.append(f"'{dep_name}' is 2 edits away from '{popular}'")

            # Dash/underscore confusion
            if (
                dep_lower.replace("-", "") == popular.replace("-", "")
                and dep_lower != popular
            ):
                suspects.append(f"'{dep_name}' dash-confusion with '{popular}'")

            # Homoglyph (1/l, 0/o)
            norm_dep = dep_lower.replace("1", "l").replace("0", "o")
            norm_pop = popular.replace("1", "l").replace("0", "o")
            if norm_dep == norm_pop and dep_lower != popular:
                suspects.append(f"'{dep_name}' homoglyph of '{popular}'")

        if suspects:
            findings.append(
                Finding(
                    rule_id="typosquat_suspect",
                    severity=Severity.HIGH,
                    surface=Surface.SOURCE_CODE,
                    title=f"Possible typosquatting: {dep_name}",
                    evidence="; ".join(suspects[:3]),
                    location="package.json:0",
                    detail=(
                        "This dependency name is very similar to a popular package. "
                        "Typosquatting is a common supply chain attack vector."
                    ),
                    confidence=0.6,
                )
            )

    return findings
