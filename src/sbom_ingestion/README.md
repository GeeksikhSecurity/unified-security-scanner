# sbom_ingestion

Python service module inside the TypeScript `unified-security-scanner` repo.
Implements **SAY-106** — the flexible SBOM ingestion bridge that feeds the
SAY-105 enrichment pipeline (OSV.dev / EPSS / KEV / OSSF Scorecard).

## Why Python in a TypeScript repo

The enrichment pipeline in `sbom-debt` (APA internal) is production-tested
Python. Rewriting to TypeScript would duplicate 80% tested code for zero
functional gain. Instead, `sbom_ingestion` runs as a sidecar Python service
that the TS orchestrator calls over stdin/stdout or a local HTTP endpoint.

## Public API

```python
from sbom_ingestion import (
    SBOMBridge,          # Detect → Reuse → Generate (4-step priority)
    CycloneDXParser,     # CycloneDX 1.4/1.5 → PackageModel
    PackageModel,        # Shared contract for all enrichment adapters
    DepsDev,             # Package → GitHub repo mapping for Scorecard
    VercelOnboarding,    # 3-entry-point marketplace flow
)
```

## Ingestion priority (Level 3 of CLAUDE.md)

1. Explicit SBOM file path provided → parse directly
2. GitHub Dependency Graph API → fetch if repo has it enabled (free, no syft)
3. Local SBOM file in repo root → reuse (`sbom.*.json`, `*.spdx.json`, `bom.json`)
4. Fall back to `syft` generation (last resort)

## Format matrix

| Format          | Versions  | Source                       | Parser              |
|-----------------|-----------|------------------------------|---------------------|
| SPDX JSON       | 2.3       | AWS Inspector, syft          | Built-in (minimal)  |
| CycloneDX JSON  | 1.4, 1.5  | GitHub export, syft          | `CycloneDXParser`   |

Both parsers emit the same `PackageModel` — enrichment code is format-agnostic.

## Running tests

```bash
cd <repo-root>
PYTHONPATH=src python3 -m unittest discover -s tests/sbom_ingestion -v
# Ran 88 tests in 0.03s — OK
```

## Integration points

- **SAY-105 enrichment adapters** consume `PackageModel` directly — no changes
  required. `DepsDev.enrich_packages()` runs as a pre-step before
  `ScorecardAdapter` to fill `source_repo`.
- **Vercel marketplace onboarding** uses `VercelOnboarding` to route the three
  entry points (Repo URL / SBOM Upload / AWS S3) into a unified pipeline.
- **CLAUDE.md** at repo root documents the full behavioral pyramid that
  governs how this module is driven.

## Status

- Phase 1 (`sbom_bridge.py`): complete, 4 resolution paths tested
- Phase 2 (`cyclonedx_parser.py`): complete, 1.4 + 1.5 round-trip tested
- Phase 3 (`deps_dev.py`): complete, 30d cache, GitHub slug extraction
- Phase 4 (`CLAUDE.md`): complete, 5-level pyramid at repo root
- Phase 5 (`vercel_onboarding.py`): complete, 3 entry points tested

Tests: 88 / 88 passing.
