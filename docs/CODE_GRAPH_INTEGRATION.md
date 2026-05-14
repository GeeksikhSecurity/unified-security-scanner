# Code-Graph Integration

The Enhanced Security Scanner integrates with the `code-graph` skill (TrailMark wrapper from [GeeksikhSecurity/claude-skills](https://github.com/GeeksikhSecurity/claude-skills)) to attach call-graph context to each finding. This converts the scanner's output from "where the bug is" to "where the bug is **and what it touches**" — the difference between a SOC2 audit checklist and a real risk assessment for client deliverables.

## What graph enrichment adds

For each finding, the enriched output attaches:

- **Callers** — who reaches this code? (Is it on a hot path or a dead branch?)
- **Blast radius** — how many functions does the affected code touch?
- **Entrypoint reachability** — is this finding actually reachable from an HTTP handler, CLI entry, or queue consumer?

Effect on prioritization: a vulnerability in a leaf utility function ranks lower than the same vulnerability in a function reachable from 12 HTTP endpoints, even at the same CVSS score.

## Prerequisites

- `jq` — `brew install jq`
- `code-graph` skill installed:
  ```bash
  cd ~
  git clone https://github.com/GeeksikhSecurity/claude-skills.git
  ./claude-skills/code-graph/install.sh
  ```
- Optional: Python 3.13 if you're on 3.14+ (see code-graph FAQ for the known TrailMark + Python 3.14 upstream issue).

## Quick start

```bash
# 1. Run the scanner as usual
pnpm run scan -- /path/to/target/code

# 2. Enrich the findings with graph context
./scripts/enrich-with-graph.sh reports/results.json \
  --repo /path/to/target/code \
  --output reports/results-enriched.json

# 3. (Or for SARIF input from Semgrep / CodeQL)
./scripts/enrich-with-graph.sh reports/semgrep.sarif \
  --repo /path/to/target/code \
  --output reports/semgrep-enriched.sarif
```

## Behavior when code-graph is unavailable

The script is **non-blocking**. If `code-graph` isn't installed (or fails on the codebase), the input file is passed through unchanged with an explanatory warning in `metadata.warnings`. Exit code stays 0 so CI/CD pipelines continue.

This matters because the scanner runs in many environments (CI, client laptops, AWS Q Developer chats, Cursor) where TrailMark may not be installed.

## Input formats

The script accepts:

1. **SARIF 2.1.0** — preferred. Direct pass-through to `cg-sarif-overlay`.
2. **Enhanced Security Scanner native `results.json`** — auto-converted to minimal SARIF, then enriched.

It detects format automatically by checking for the relevant top-level fields (`.version + .runs` for SARIF, `.scanId + .toolsRun` for native).

## Where to insert in your scan pipeline

Add as a post-scan step in your `package.json` scripts or CI YAML:

```json
{
  "scripts": {
    "scan": "node dist/index.js scan",
    "scan:enrich": "./scripts/enrich-with-graph.sh reports/results.json --repo . --output reports/results-enriched.json",
    "scan:full": "pnpm scan && pnpm scan:enrich"
  }
}
```

For client engagements, run `scan:full` and ship `results-enriched.json` instead of `results.json`.

## What this is NOT

- Not a replacement for the scanner's existing AI validation phase.
- Not a vulnerability scanner itself — code-graph adds *context* to existing findings, it doesn't find new ones.
- Not a hard dependency. The scanner works fine without it; the enrichment script gracefully degrades.

## Related work

- **code-graph skill** (TrailMark wrapper): [SAY-222](https://linear.app/sayvainc/issue/SAY-222) · [Notion](https://www.notion.so/360596e06bd581a2a06af12e31d15524) · [SKILL.md](https://github.com/GeeksikhSecurity/claude-skills/blob/main/code-graph/SKILL.md)
- **claude-code-error-prevention v1.3.0**: Same graph backend, used for AI-coding-agent rules. [SAY-221](https://linear.app/sayvainc/issue/SAY-221)
- **Sayva security-scripts** (`/Volumes/2TBSSD/security-scripts`): Sister Sayva consulting toolkit. Same code-graph backend; same `cg-sarif-overlay` integration pattern.
- **APA `apaops-isec_scripts` dashboard**: Uses code-graph's `cg-complexity-hotspots` for the technical-debt visualization layer.

## Troubleshooting

**`code-graph not available; using heuristic estimate` in warnings**

Run the install:
```bash
~/claude-skills/code-graph/install.sh
```

If you don't have the repo:
```bash
git clone https://github.com/GeeksikhSecurity/claude-skills.git ~/claude-skills
~/claude-skills/code-graph/install.sh
```

**`TrailMark failed to index repo: 'builtins.Parser' object has no attribute 'parse'`**

Known TrailMark + Python 3.14 upstream issue. See [code-graph FAQ](https://github.com/GeeksikhSecurity/claude-skills/blob/main/code-graph/FAQ.md). Workaround: `brew install python@3.13 && CODEGRAPH_PYTHON=/opt/homebrew/bin/python3.13 ~/claude-skills/code-graph/install.sh`

**Enriched output is identical to input**

Either code-graph isn't installed (check `metadata.warnings`) or the target repo wasn't found / contained no parseable source. Check `--repo` points at the right path.
