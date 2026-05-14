#!/usr/bin/env bash
# enrich-with-graph.sh — augment scanner findings with code-graph context.
#
# Pipeline integration for the Enhanced Security Scanner. Reads scan output
# (SARIF or the scanner's native results.json), attaches graph context to
# each finding (callers, blast radius, entrypoint reachability) via the
# code-graph skill (TrailMark wrapper), and emits enriched output.
#
# Adds a critical missing layer to client deliverables: "this finding at
# line 42" becomes "this finding at line 42 is reachable from 4 HTTP
# entrypoints via 3 call paths" — the difference between a SOC2 checklist
# and a real risk assessment.
#
# Usage:
#   ./scripts/enrich-with-graph.sh <input-file> [--repo <target-repo>] [--output <file>]
#
# Examples:
#   # Enrich a SARIF file from Semgrep:
#   ./scripts/enrich-with-graph.sh reports/semgrep.sarif --repo /path/to/scanned/code
#
#   # Enrich the scanner's native JSON output:
#   ./scripts/enrich-with-graph.sh reports/results.json --repo . --output reports/results-enriched.json
#
# Requirements:
#   - jq (brew install jq)
#   - code-graph skill installed:
#     git clone https://github.com/GeeksikhSecurity/claude-skills && \
#       ./claude-skills/code-graph/install.sh
#
# Behavior when code-graph is unavailable:
#   - Emits input unchanged with a note in metadata.warnings
#   - Exits 0 so this script is safe to wedge into pipelines
#
# Backed by: https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/

set -uo pipefail

CG_DIR="${CODEGRAPH_SKILL_DIR:-$HOME/.claude/skills/code-graph}"
CG_SARIF_OVERLAY="$CG_DIR/scripts/cg-sarif-overlay.sh"
CG_VENV_PY="$CG_DIR/.venv/bin/python"

INPUT_FILE=""
TARGET_REPO="$PWD"
OUTPUT_FILE=""

usage() {
  cat <<EOF
Usage:
  $(basename "$0") <input-file> [--repo <path>] [--output <file>]

Arguments:
  <input-file>      SARIF or results.json from the scanner
  --repo <path>     Target code repo to query (default: cwd)
  --output <file>   Where to write enriched output (default: stdout)

Environment:
  CODEGRAPH_SKILL_DIR   Override code-graph location (default: ~/.claude/skills/code-graph)

When code-graph is unavailable, the input is passed through unchanged
with an explanatory warning. Exit 0 in both cases so pipelines stay
unbroken. Exit non-zero only on usage errors or missing input files.
EOF
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) TARGET_REPO="$2"; shift 2 ;;
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --*) echo "Unknown flag: $1" >&2; usage >&2; exit 2 ;;
    *)
      if [[ -z "$INPUT_FILE" ]]; then
        INPUT_FILE="$1"; shift
      else
        echo "Unexpected positional: $1" >&2; usage >&2; exit 2
      fi
      ;;
  esac
done

[[ -z "$INPUT_FILE" ]] && { usage >&2; exit 2; }
[[ ! -f "$INPUT_FILE" ]] && { echo "Input file not found: $INPUT_FILE" >&2; exit 3; }
command -v jq >/dev/null 2>&1 || { echo "jq required; brew install jq" >&2; exit 4; }

# Detect code-graph availability
is_code_graph_available() {
  [[ -x "$CG_VENV_PY" ]] || return 1
  [[ -x "$CG_SARIF_OVERLAY" ]] || return 1
  "$CG_VENV_PY" -c "import trailmark" 2>/dev/null || return 1
  return 0
}

# Detect input format: SARIF vs scanner-native results.json
is_sarif() {
  jq -e '.version != null and .runs != null' "$1" >/dev/null 2>&1
}

is_scanner_native() {
  jq -e '.scanId != null and .toolsRun != null' "$1" >/dev/null 2>&1
}

# Convert scanner-native results.json into a minimal SARIF document so
# cg-sarif-overlay can process it. Lossy — preserves only what code-graph
# needs (locations + rule IDs).
convert_native_to_sarif() {
  local input="$1"
  jq '{
    "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
      "tool": {
        "driver": {
          "name": "enhanced-security-scanner",
          "version": (.version // "unknown")
        }
      },
      "results": (
        (.findings // .vulnerabilities // .results // [])
        | map({
            "ruleId": (.ruleId // .id // .type // "unknown"),
            "level": (.severity // "warning"),
            "message": { "text": (.message // .description // "") },
            "locations": [{
              "physicalLocation": {
                "artifactLocation": { "uri": (.file // .location // "unknown") },
                "region": { "startLine": (.line // .lineNumber // 1) }
              }
            }]
          })
      )
    }]
  }' "$input"
}

# ---------- Main ----------

if ! is_code_graph_available; then
  # Pass through with warning
  jq '. + {
    "metadata": ((.metadata // {}) + {
      "graph_enrichment": "skipped",
      "warnings": (((.metadata // {}).warnings // []) + ["code-graph not available; install from https://github.com/GeeksikhSecurity/claude-skills/blob/main/code-graph/install.sh"])
    })
  }' "$INPUT_FILE" > "${OUTPUT_FILE:-/dev/stdout}"
  [[ -n "$OUTPUT_FILE" ]] && echo "code-graph unavailable; passed input through to $OUTPUT_FILE" >&2
  exit 0
fi

# Determine input format and convert to SARIF if needed
TMP_SARIF=""
trap 'rm -f "$TMP_SARIF"' EXIT
if is_sarif "$INPUT_FILE"; then
  SARIF_INPUT="$INPUT_FILE"
elif is_scanner_native "$INPUT_FILE"; then
  TMP_SARIF=$(mktemp -t enrich-graph.XXXXXX.sarif)
  convert_native_to_sarif "$INPUT_FILE" > "$TMP_SARIF"
  SARIF_INPUT="$TMP_SARIF"
else
  echo "Input file is neither SARIF nor scanner-native results.json" >&2
  echo "Expected: SARIF (.version + .runs) or scanner output (.scanId + .toolsRun)" >&2
  exit 5
fi

# Run cg-sarif-overlay. Capture stdout and stderr separately so we can
# detect failures even when cg-* emits a JSON-shaped error envelope.
TMP_STDERR=$(mktemp -t enrich-graph-err.XXXXXX)
ENRICHED=$("$CG_SARIF_OVERLAY" "$SARIF_INPUT" --repo "$TARGET_REPO" 2>"$TMP_STDERR" || true)
STDERR_CAPTURE=$(cat "$TMP_STDERR" 2>/dev/null || true)
rm -f "$TMP_STDERR"

# Failure indicators:
# - empty stdout
# - envelope shape but with result=null (cg-* always emits result=null on error)
# - presence of .error field
ENRICHMENT_FAILED=0
if [[ -z "$ENRICHED" ]]; then
  ENRICHMENT_FAILED=1
elif echo "$ENRICHED" | jq -e '.result == null or (.error // null) != null' >/dev/null 2>&1; then
  ENRICHMENT_FAILED=1
elif ! echo "$ENRICHED" | jq -e '.schema_version == 1' >/dev/null 2>&1; then
  ENRICHMENT_FAILED=1
fi

if [[ "$ENRICHMENT_FAILED" -eq 1 ]]; then
  # Prefer the error message from the envelope, fall back to stderr capture
  ERR_MSG=$(echo "$ENRICHED" | jq -r '.error // empty' 2>/dev/null)
  [[ -z "$ERR_MSG" ]] && ERR_MSG=$(echo "$STDERR_CAPTURE" | head -c 200 | tr -d '\n')
  [[ -z "$ERR_MSG" ]] && ERR_MSG="unknown error"
  jq --arg err "$ERR_MSG" '. + {
    "metadata": ((.metadata // {}) + {
      "graph_enrichment": "failed",
      "warnings": (((.metadata // {}).warnings // []) + [("code-graph query failed: " + $err)])
    })
  }' "$INPUT_FILE" > "${OUTPUT_FILE:-/dev/stdout}"
  [[ -n "$OUTPUT_FILE" ]] && echo "code-graph errored; passed input through to $OUTPUT_FILE (err: $ERR_MSG)" >&2
  exit 0
fi

# Write enriched output
if [[ -n "$OUTPUT_FILE" ]]; then
  echo "$ENRICHED" > "$OUTPUT_FILE"
  echo "Enriched output written to $OUTPUT_FILE" >&2
else
  echo "$ENRICHED"
fi
