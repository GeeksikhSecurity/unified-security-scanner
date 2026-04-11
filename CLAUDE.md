# CLAUDE.md — unified-security-scanner
# Behavioral Rules Pyramid for AI-Assisted Development
#
# Complements Cubic.dev auto-wiki (structural docs).
# This file carries judgment, sequencing, and compliance constraints
# that only the author can encode — the auto-wiki cannot infer these.
#
# Author: Gurvinder Singh (jasgur@proton.me)
# Last updated: 2026-04-09
# Related: SAY-106, SAY-105, SAY-71, SAY-104

---

## Level 0 — Project Identity & Positioning

**What this is:**
An enterprise-grade AI-powered security analysis tool that combines:
- Phase 1: Traditional SAST (Semgrep + CodeQL)
- Phase 2: AI-Enhanced Analysis (LLM validation, <5% false positive rate)
- Phase 3: Targeted Deep Dive (function-level, multi-file, critical findings only)
- SBOM enrichment layer: OSV.dev + OSSF Scorecard + EPSS + KEV + deps.dev

**What this is not:**
- Not a code quality scorer (that is Codacy's focus)
- Not an LLM evaluation framework (that is Promptfoo's focus)
- Not a standalone SAST tool (Semgrep/CodeQL are inputs, not the product)
- Not a replacement for human security review — it is a triage and prioritisation layer

**Differentiators vs. Codacy and Cubic.dev:**
- SBOM-level enrichment: KEV + EPSS + OSSF Scorecard in a single weighted debt score
- Compliance mapping output: findings mapped to ASVS 5.0, HECVAT 4.0, AISVS (paid tier)
- AI workload identity coverage: model API keys, agent service accounts (novel — not in ASVS 5.0)
- False positive SLA: <5% is a hard constraint, not a target — FP Reducer enforces this

**Hard constraint on false positive rate:**
The <5% FPR is a product SLA. It is not a guideline. Increasing recall at the cost of
precision violates this constraint. When in doubt, surface as UNCERTAIN rather than as a
confirmed finding.

---

## Level 1 — Agent Role Rules (non-negotiable)

These rules govern which Claude model handles which task. They are not
performance optimisations — they are correctness constraints.

```
claude-sonnet-4-6   = execution default
                      All scan phases (1, 2, 3), enrichment calls, report generation.
                      Never use a slower model for execution tasks.

claude-opus-4-6     = planning only
                      Architecture decisions, rule design, pipeline design.
                      NEVER invoked during scan execution.
                      NEVER used for per-finding analysis (cost and latency prohibitive).

claude-haiku-4-5    = classify and extract only
                      FP Reducer category tagging, severity classification,
                      ecosystem detection from manifest snippets.
                      Not used for security reasoning or finding validation.
```

**Agentic step limit:**
- MAX 15 steps per scan run
- Stop condition is evaluated FIRST at each step, not last
- Stop condition: CRITICAL finding confirmed → escalate immediately, halt further scanning
- Do not continue scanning a codebase after a confirmed CRITICAL finding without explicit continuation instruction

**No unbounded loops:**
Phase 2 LLM validation runs maximum 3 iterations per finding.
If confidence < 0.7 after 3 iterations, classify as UNCERTAIN — do not suppress and do not loop further.

---

## Level 2 — Phase Sequencing Rules

**Phase 1 (SAST — Semgrep + CodeQL):**
- Findings from Phase 1 are facts, not candidates
- Phase 2 confirms and contextualises Phase 1 findings — it does not re-litigate them
- Phase 2 may raise severity (additional context reveals worse impact)
- Phase 2 may lower confidence (context reveals a false positive pattern)
- Phase 2 NEVER suppresses a Phase 1 finding on its own authority — it flags for FP Reducer

**Phase 2 (AI-Enhanced Analysis):**
- Maximum 3 LLM iterations per finding (hard limit)
- Confidence threshold for confirmation: ≥ 0.7
- Confidence < 0.7 after 3 iterations → UNCERTAIN status, surface to human reviewer
- Secrets findings: NEVER suppressed by Phase 2 on confidence alone
  Rationale: a secret that is a false positive costs a human 30 seconds to verify.
  A secret that is suppressed and is real costs an incident.

**Phase 3 (Deep Dive — function-level, multi-file):**
- Triggers ONLY when ALL of the following are true:
  - Severity = CRITICAL
  - AND (CVSS ≥ 9.0 OR KEV-flagged)
- Phase 3 does not run on HIGH findings without explicit override
- Phase 3 output is a structured multi-file analysis, not a finding re-statement

**FP Reducer:**
- Operates after Phase 2
- Uses claude-haiku-4-5 for pattern classification (see Level 1)
- Hard floor: if FP Reducer would push confirmed findings below <5% FPR threshold,
  do not suppress further — surface remaining findings as UNCERTAIN

---

## Level 3 — SBOM Enrichment Rules

**Detection priority (SBOMBridge.resolve_sbom):**
```
1. Explicit file path provided          → parse directly (never regenerate)
2. GitHub Dependency Graph API          → fetch if enabled (check before syft)
3. Local SBOM discovery                 → glob standard filenames in repo root
4. Fallback                             → generate via syft (last resort only)
```

Cache key: `{repo_slug}_{git_sha[:8]}` — skip all generation steps on cache hit.
Never regenerate an SBOM for a commit that is already cached.

**Format support:**
- SPDX 2.3 JSON: primary format — use sbom-debt SPDXParser if importable (production-tested at APA)
- CycloneDX 1.4/1.5 JSON: GitHub export and syft output — use CycloneDXParser
- Both parsers output to PackageModel — enrichment pipeline is format-agnostic
- Do NOT rewrite sbom-debt enrichment adapters — import or copy tested code

**Enrichment priority order (scoring):**
```
KEV flag (actively exploited)        → CRITICAL regardless of CVSS
EPSS ≥ 0.7                           → HIGH (exploitation likely)
CVSS ≥ 9.0                           → CRITICAL
OSSF Scorecard < 3                   → CRITICAL (regardless of CVE status)
Maintained=false + any CVE           → CRITICAL (compounding risk, not additive)
OSSF Scorecard 3–5 + medium CVE      → HIGH
OSSF Scorecard < 5 (no CVE)          → WATCH
```

**deps.dev usage:**
Use deps.dev API for package → GitHub repo mapping required by OSSF Scorecard lookups.
Do not rewrite this adapter — port from sbom-debt (production-tested).

**Enrichment cache TTLs (from sbom-debt production spec):**
```
OSV.dev       7 days
KEV           24 hours   (catalog changes frequently)
EPSS          7 days
Scorecard     30 days
deps.dev      30 days
```

**Enrichment health monitoring:**
Alert if `enrichment_success_rate` drops below 80%.
This threshold is from sbom-debt production monitoring — do not lower it.

**syft invocation constraints:**
- Only invoked in Step 4 (fallback) — never as a first resort
- Format preference: SPDX JSON default, CycloneDX JSON if caller specifies
- Output to `sbom_cache/` only — never to the scanned repo directory
- Timeout: 120 seconds. Raise SBOMBridgeError if exceeded.

---

## Level 4 — Compliance Mapping Rules

**Every finding must carry a framework mapping before report generation.**
A CRITICAL finding without a compliance mapping blocks report generation.
This is enforced in the output layer, not as a suggestion.

**Mandatory mappings by finding category:**

| Finding Category        | ASVS 5.0 Mapping          | HECVAT 4.0 Section              |
|-------------------------|---------------------------|----------------------------------|
| Supply Chain            | V13.2 (dependency security) | Third-party integrations        |
| Secrets / Credentials   | V2.10 (service credentials) | API + integration security      |
| Injection (SQL/XSS/cmd) | V5 (validation/sanitization)| Input validation                |
| Authentication          | V2 (authentication)        | Access control                  |
| Access Control          | V4 (access control)        | Privileged access management    |
| Cryptography            | V6 (cryptography)          | Data protection                 |
| API Security            | V13.1 (generic web API)    | API + integration security      |
| Logging / Monitoring    | V7 (error handling/logging)| Audit and logging               |

**AI workload identity gap (AISVS — not yet in ASVS 5.0 or HECVAT 4.0):**
Model API keys, inference endpoint credentials, and AI agent service accounts
are first-class workload identities. They are not covered by ASVS V2.10 (written
for traditional service principals). Flag these findings with:
  `compliance_mapping: "AISVS-PENDING — SAY-71 contribution"`

This gap is a genuine novel contribution to SAY-71 (Security Baseline Framework).
Do not map AI workload identity findings to ASVS V2.10 as a workaround —
surface the gap explicitly.

**Patreon compliance mappings (paid tier unlock):**
Extended compliance mappings (purchased from Patreon, March 2026) are applied
at the paid report tier. They are not free-tier output. The mapping logic lives in
`src/compliance/patreon_mappings.py` — do not inline into parsers or enrichment adapters.

**Report generation gate:**
```python
# Enforced in report generator — do not bypass
if any(f.compliance_mapping is None for f in critical_findings):
    raise ReportGenerationError(
        f"{sum(1 for f in critical_findings if f.compliance_mapping is None)} "
        "CRITICAL finding(s) lack compliance mapping — resolve before generating report"
    )
```

---

## Level 5 — Output Constraints

**Two-layer output (always):**
```
Layer 1: Human Markdown — CISO-readable narrative, findings table, board talking points
Layer 2: Machine JSON   — CI/CD integration, Linear ticket generation, scoring data
```
Never invert this order. The Markdown layer is what a human reads.
The JSON layer is what a pipeline consumes.
Pattern established in SAY-72 (whatsonmybill.com) — apply consistently here.

**SARIF output:**
- Required for GitHub Security tab native integration
- Block PR on severity ≥ CRITICAL (configurable via `security.json` `failOn`)
- SARIF rules must include `helpUri` linking to the ASVS control for each finding

**Markdown report requirements:**
Every finding in the Markdown report must include:
- CVE ID or GHSA ID (never raw package name alone)
- fix_version (if available from OSV.dev) or "No fix available as of {date}"
- remediation_eta (derivable from KEV deadline if KEV-flagged)
- compliance_mapping (ASVS + HECVAT reference)

**CISO executive summary (required section):**
```
N packages scanned
X critical findings (Y KEV-flagged, Z with EPSS ≥ 0.7)
A dependencies abandoned (OSSF Maintained=false)
B AI-generated hygiene failures (Scorecard checks: Dependency-Pinning=0, CI-Tests=0, etc.)
```
This section is mandatory. It is the first thing a CISO reads.

**Linear ticket auto-generation:**
- CRITICAL findings only
- One ticket per finding cluster (not per CVE — group by package)
- Ticket must include: package, version, CVE IDs, fix_version, compliance_mapping, EPSS score
- Label: "Security" + severity tier
- Do not generate tickets for UNCERTAIN findings — those require human triage first

**Report blocking conditions:**
```
BLOCK if: any CRITICAL finding missing compliance_mapping    (Level 4 gate)
BLOCK if: enrichment_success_rate < 80%                     (Level 3 gate)
BLOCK if: Phase 2 ran 0 iterations (enrichment skipped)     (data quality gate)
WARN  if: any package has version = "NOASSERTION"           (cannot enrich)
WARN  if: syft was used AND git_sha is None                 (non-deterministic scan)
```

---

## Development Conventions

**Model usage in code:**
```python
# Correct
EXECUTION_MODEL = "claude-sonnet-4-6"    # Phase 1–3, enrichment, reports
PLANNING_MODEL  = "claude-opus-4-6"      # Architecture only — not in scan path
EXTRACT_MODEL   = "claude-haiku-4-5-20251001"  # FP Reducer, classify/extract

# Never use PLANNING_MODEL in scan execution paths
# Never use EXTRACT_MODEL for security reasoning
```

**Reuse before rewrite:**
- sbom-debt SPDXParser → import if sbom-debt is installed; fall back to built-in SPDX parser
- sbom-debt deps.dev adapter → copy to `src/sbom_ingestion/deps_dev.py`, do not rewrite
- sbom-debt enrichment cache TTL design → replicate exactly (production-proven TTL values)

**Testing:**
- All 4 SBOMBridge resolution paths must have unit tests
- CycloneDXParser round-trip test: GitHub export fixture → enrich → verify package count
- Never mock the enrichment pipeline in integration tests — use cached fixtures instead
- FPR assertion in CI: scanner output on fixture codebase must stay below 5%

**Cubic.dev auto-wiki:**
This `CLAUDE.md` complements the auto-wiki at:
https://www.cubic.dev/wiki/GeeksikhSecurity/unified-security-scanner

The auto-wiki covers: component paths, API signatures, performance metrics, CI/CD pipeline.
This file covers: judgment, sequencing, compliance intent, agent role constraints.
Neither replaces the other.
