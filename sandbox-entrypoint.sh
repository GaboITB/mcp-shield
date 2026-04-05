#!/bin/bash
# MCP Shield Sandbox — Entrypoint Script
# Installs an MCP server, monitors its behavior, and reports findings.
#
# Arguments:
#   $1 = source (GitHub URL, npm package, or pip package)
#   $2 = type (npm|pip|git)
#   $3 = duration in seconds (default: 30)

set -euo pipefail

SOURCE="${1:?Usage: sandbox-entrypoint.sh <source> <type> <duration>}"
MCP_TYPE="${2:-npm}"
DURATION="${3:-30}"

LOGDIR="/audit/logs"
CAPDIR="/audit/capture"

echo "=== MCP Shield Sandbox ==="
echo "Source: ${SOURCE}"
echo "Type: ${MCP_TYPE}"
echo "Duration: ${DURATION}s"
echo ""

# ─── Phase 1: Install the MCP server ──────────────────────────
echo "--- Phase 1: Installation ---"

case "${MCP_TYPE}" in
npm)
  echo "[*] Installing via npm: ${SOURCE}"
  npm init -y >/dev/null 2>&1
  # Capture postinstall behavior
  strace -f -e trace=network,process -o "${LOGDIR}/install_strace.log" \
    npm install "${SOURCE}" --ignore-scripts=false 2>&1 | tee "${LOGDIR}/install.log" || true
  ;;
pip)
  echo "[*] Installing via pip: ${SOURCE}"
  strace -f -e trace=network,process -o "${LOGDIR}/install_strace.log" \
    python3 -m pip install "${SOURCE}" 2>&1 | tee "${LOGDIR}/install.log" || true
  ;;
git)
  echo "[*] Cloning from git: ${SOURCE}"
  git clone --depth 1 "${SOURCE}" /audit/source 2>&1 | tee "${LOGDIR}/install.log" || true
  if [ -f /audit/source/package.json ]; then
    cd /audit/source
    npm install --ignore-scripts=false 2>&1 | tee -a "${LOGDIR}/install.log" || true
  elif [ -f /audit/source/requirements.txt ]; then
    python3 -m pip install -r /audit/source/requirements.txt 2>&1 | tee -a "${LOGDIR}/install.log" || true
  elif [ -f /audit/source/pyproject.toml ]; then
    python3 -m pip install /audit/source 2>&1 | tee -a "${LOGDIR}/install.log" || true
  fi
  ;;
local)
  echo "[*] Using local mount: ${SOURCE}"
  # Source is mounted at /audit/source as read-only volume
  # Copy to writable location for execution
  cp -r /audit/source /tmp/mcp-local 2>/dev/null || true
  if [ -d /tmp/mcp-local/node_modules ]; then
    echo "[*] node_modules found, skipping install"
    cd /tmp/mcp-local
  elif [ -f /tmp/mcp-local/package.json ]; then
    echo "[*] Installing npm dependencies from local source..."
    cd /tmp/mcp-local
    strace -f -e trace=network,process -o "${LOGDIR}/install_strace.log" \
      npm install --ignore-scripts=false 2>&1 | tee "${LOGDIR}/install.log" || true
  elif [ -f /tmp/mcp-local/requirements.txt ]; then
    echo "[*] Installing pip dependencies from local source..."
    strace -f -e trace=network,process -o "${LOGDIR}/install_strace.log" \
      python3 -m pip install -r /tmp/mcp-local/requirements.txt 2>&1 | tee "${LOGDIR}/install.log" || true
  elif [ -f /tmp/mcp-local/pyproject.toml ]; then
    echo "[*] Installing pip package from local source..."
    strace -f -e trace=network,process -o "${LOGDIR}/install_strace.log" \
      python3 -m pip install /tmp/mcp-local 2>&1 | tee "${LOGDIR}/install.log" || true
  else
    echo "[*] No manifest found, skipping install"
  fi
  ;;
*)
  echo "[!] Unknown type: ${MCP_TYPE}"
  exit 1
  ;;
esac

echo "[+] Installation complete"
echo ""

# ─── Phase 2: Start monitoring ────────────────────────────────
echo "--- Phase 2: Monitoring (${DURATION}s) ---"

# Start tcpdump (capture all network traffic)
tcpdump -i any -w "${CAPDIR}/traffic.pcap" -Z root 2>/dev/null &
TCPDUMP_PID=$!

# Start filesystem monitoring (watch sensitive paths)
inotifywait -m -r --timefmt '%Y-%m-%d %H:%M:%S' --format '%T %e %w%f' \
  /etc /root /home /tmp /var \
  >"${LOGDIR}/filesystem.log" 2>/dev/null &
INOTIFY_PID=$!

# ─── Phase 3: Run the MCP server ──────────────────────────────
echo "[*] Attempting to start MCP server..."

# Find the main entry point — build as an array to avoid shell injection
# (C2 fix: package.json "main" field could contain shell metacharacters)
ENTRY_BIN=""
ENTRY_ARG=""

if [ -d /tmp/mcp-local ] && [ -f /tmp/mcp-local/package.json ]; then
  # Local mount — entry point from the copied local source
  MAIN=$(node -e "const p=require('/tmp/mcp-local/package.json'); console.log(p.main || p.bin && Object.values(p.bin)[0] || 'index.js')" 2>/dev/null || echo "index.js")
  if echo "${MAIN}" | grep -qE '^[a-zA-Z0-9_./-]+$'; then
    ENTRY_BIN="node"
    ENTRY_ARG="/tmp/mcp-local/${MAIN}"
  else
    echo "[!] Unsafe entry point in package.json: ${MAIN}"
    ENTRY_BIN="echo"
    ENTRY_ARG="Unsafe entry point blocked"
  fi
elif ls /mcp/node_modules/.bin/* >/dev/null 2>&1; then
  ENTRY_POINT="$(ls /mcp/node_modules/.bin/ | head -1)"
  ENTRY_BIN="node"
  ENTRY_ARG="/mcp/node_modules/.bin/${ENTRY_POINT}"
elif [ -f /audit/source/package.json ]; then
  # Extract main safely via node, then validate it's a simple path
  MAIN=$(node -e "const p=require('/audit/source/package.json'); console.log(p.main || p.bin && Object.values(p.bin)[0] || 'index.js')" 2>/dev/null || echo "index.js")
  # Validate: only allow alphanumeric, dots, hyphens, underscores, slashes
  if echo "${MAIN}" | grep -qE '^[a-zA-Z0-9_./-]+$'; then
    ENTRY_BIN="node"
    ENTRY_ARG="/audit/source/${MAIN}"
  else
    echo "[!] Unsafe entry point in package.json: ${MAIN}"
    ENTRY_BIN="echo"
    ENTRY_ARG="Unsafe entry point blocked"
  fi
elif [ -f /audit/source/setup.py ] || [ -f /audit/source/pyproject.toml ]; then
  MODULE_NAME=$(basename /audit/source)
  if echo "${MODULE_NAME}" | grep -qE '^[a-zA-Z0-9_.-]+$'; then
    ENTRY_BIN="python3"
    ENTRY_ARG="-m ${MODULE_NAME}"
  else
    ENTRY_BIN="echo"
    ENTRY_ARG="Unsafe module name blocked"
  fi
else
  ENTRY_BIN="echo"
  ENTRY_ARG="No entry point found"
fi

echo "[*] Entry: ${ENTRY_BIN} ${ENTRY_ARG}"

# Run with strace — word-split ENTRY_ARG intentionally (it may contain flags like "-m module")
# shellcheck disable=SC2086
timeout "${DURATION}" strace -f -e trace=network,process,openat,connect \
  -o "${LOGDIR}/runtime_strace.log" \
  "${ENTRY_BIN}" ${ENTRY_ARG} \
  >"${LOGDIR}/mcp_stdout.log" 2>"${LOGDIR}/mcp_stderr.log" || true

echo "[+] MCP server exited"
echo ""

# ─── Phase 4: Stop monitoring and analyze ─────────────────────
echo "--- Phase 3: Analysis ---"

# Stop background processes
kill "${TCPDUMP_PID}" 2>/dev/null || true
kill "${INOTIFY_PID}" 2>/dev/null || true
sleep 1

# ─── Analyze: DNS queries ─────────────────────────────────────
echo "=== DNS queries ==="
if [ -f "${CAPDIR}/traffic.pcap" ] && [ -s "${CAPDIR}/traffic.pcap" ]; then
  tcpdump -r "${CAPDIR}/traffic.pcap" -nn 'port 53' 2>/dev/null |
    grep -oP '(?<=A\? )\S+' | sort -u || echo "(none)"
else
  echo "(no capture)"
fi
echo ""

# ─── Analyze: TCP connections ─────────────────────────────────
echo "=== TCP connections ==="
if [ -f "${CAPDIR}/traffic.pcap" ] && [ -s "${CAPDIR}/traffic.pcap" ]; then
  tcpdump -r "${CAPDIR}/traffic.pcap" -nn 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0' 2>/dev/null |
    awk '{print $5}' | sort -u || echo "(none)"
else
  echo "(no capture)"
fi
echo ""

# ─── Analyze: Sensitive files ─────────────────────────────────
echo "=== Sensitive files ==="
SENSITIVE_PATTERNS="\.env|id_rsa|\.ssh/|credentials|\.aws/|\.kube/|shadow|passwd|\.gnupg"
if [ -f "${LOGDIR}/runtime_strace.log" ]; then
  grep -oP 'openat\([^,]+, "([^"]+)"' "${LOGDIR}/runtime_strace.log" |
    grep -iE "${SENSITIVE_PATTERNS}" | sort -u || echo "(none)"
else
  echo "(no strace log)"
fi
if [ -f "${LOGDIR}/filesystem.log" ]; then
  grep -iE "${SENSITIVE_PATTERNS}" "${LOGDIR}/filesystem.log" | head -20 || true
fi
echo ""

# ─── Analyze: Processes launched ──────────────────────────────
echo "=== Processes launched ==="
if [ -f "${LOGDIR}/runtime_strace.log" ]; then
  grep -oP 'execve\("([^"]+)"' "${LOGDIR}/runtime_strace.log" |
    sed 's/execve("//; s/"$//' | sort -u || echo "(none)"
  grep -oP 'execve\("([^"]+)"' "${LOGDIR}/install_strace.log" 2>/dev/null |
    sed 's/execve("//; s/"$//' | sort -u || true
else
  echo "(no strace log)"
fi
echo ""

# ─── Analyze: External connections (strace connect syscalls) ──
echo "=== External connections ==="
if [ -f "${LOGDIR}/runtime_strace.log" ]; then
  grep 'connect(' "${LOGDIR}/runtime_strace.log" |
    grep -v '127.0.0.1\|/var/run\|/tmp/' |
    grep -oP 'sin_addr=inet_addr\("([^"]+)"\)' | sort -u || echo "(none)"
else
  echo "(no strace log)"
fi
echo ""

echo "=== Sandbox analysis complete ==="
