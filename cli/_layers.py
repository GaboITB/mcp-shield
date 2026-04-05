"""Audit layer runners (live, sandbox, bait-switch)."""

from __future__ import annotations


def run_live_layer(
    engine: "AuditEngine",
    result: "AuditResult",
    command: str,
    live_args: list[str],
    env: dict[str, str] | None,
    quiet: bool,
) -> None:
    """Layer 1b: Live fetch -- tools, resources, prompts, capabilities."""
    if not quiet:
        print(f"\n{'='*60}")
        print("[*] LAYER 1b: Live MCP protocol analysis")
        print(f"{'='*60}")
    try:
        engine.run_live(result, command, live_args, env)
        if not quiet:
            res_count = len(result.resources)
            prompt_count = len(result.prompts)
            caps = result.capabilities
            extras = []
            if res_count:
                extras.append(f"{res_count} resources")
            if prompt_count:
                extras.append(f"{prompt_count} prompts")
            if caps and caps.sampling:
                extras.append("SAMPLING capability")
            if extras:
                print(f"[+] Protocol surfaces: {', '.join(extras)}")
    except Exception as exc:
        if not quiet:
            print(f"[!] Live analysis failed: {exc}")


def run_sandbox_layer(
    source: str,
    name: str,
    result: "AuditResult",
    network: str,
    quiet: bool,
) -> None:
    """Layer 2: Docker sandbox analysis."""
    from mcp_shield.runtime.sandbox import (
        check_sandbox_prerequisites,
        run_sandbox,
    )

    ok, msg = check_sandbox_prerequisites()
    if not ok:
        if not quiet:
            print(f"[~] Sandbox skipped: {msg}")
        return

    if not quiet:
        print(f"\n{'='*60}")
        print("[*] LAYER 2: Docker sandbox analysis")
        print(f"{'='*60}")

    try:
        sandbox_result = run_sandbox(
            source=source,
            name=name,
            network=network,
        )
        if not quiet:
            print(f"[+] Sandbox completed: {sandbox_result.status}")
        sandbox_findings = sandbox_result.to_findings()
        if sandbox_result.verdict == "INCOMPLETE":
            if not quiet:
                print(
                    "[!] Sandbox INCOMPLETE -- MCP server did not start. "
                    "The sandbox ran but could not test the server."
                )
        elif sandbox_findings:
            result.findings.extend(sandbox_findings)
            if not quiet:
                print(f"[!] Sandbox verdict: {sandbox_result.verdict}")
                for finding in sandbox_findings:
                    print(
                        f"    {finding.severity.value.upper():8s} "
                        f"{finding.title}: {finding.evidence}"
                    )
        elif not quiet:
            print("[+] No suspicious runtime behavior detected")
    except Exception as exc:
        if not quiet:
            print(f"[!] Sandbox failed: {exc}")


def run_bait_switch_layer(
    command: str,
    live_args: list[str],
    result: "AuditResult",
    quiet: bool,
    env: dict[str, str] | None = None,
) -> None:
    """Layer 3: Bait-and-switch multi-identity probe."""
    from mcp_shield.runtime.bait_switch import probe_bait_switch

    if not quiet:
        print(f"\n{'='*60}")
        print("[*] LAYER 3: Bait-and-switch detection (multi-identity)")
        print(f"{'='*60}")

    try:
        bs_result = probe_bait_switch(
            command=command,
            args=live_args,
            env=env,
            thorough=True,
        )
        bs_findings = bs_result.to_findings()
        if bs_findings:
            result.findings.extend(bs_findings)
            if not quiet:
                print(f"[!] BAIT-AND-SWITCH DETECTED -- {len(bs_findings)} findings:")
                for f in bs_findings:
                    print(f"    {f.severity.value.upper():8s} {f.title}")
        elif bs_result.status == "insufficient":
            if not quiet:
                print("[~] Could not complete probe -- insufficient connections")
        elif not quiet:
            print("[+] No bait-and-switch behavior detected")
    except Exception as exc:
        if not quiet:
            print(f"[!] Bait-and-switch probe failed: {exc}")
