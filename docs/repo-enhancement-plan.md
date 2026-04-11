# GitHub Repository Enhancement Plan
## MCP Sentinel Scanner & Unified Security Scanner

**Derived from:** "Enhancing GitHub Security Scanning" Research Document
**Date:** February 8, 2026
**Author:** Gurvinder Singh | SecurityLeader.ai

---

## Executive Summary

This document maps specific research findings from the Arcanum Security frameworks, Shadow IT analysis, and AI code vulnerability data into actionable GitHub issues and feature enhancements for both the `mcp-sentinel-scanner` and `unified-security-scanner` repositories.

---

## MCP Sentinel Scanner Enhancements

### HIGH PRIORITY

#### 1. Arcanum PI Taxonomy v1.5 Detection Module
**Issue Title:** `feat: Add Arcanum Prompt Injection Taxonomy v1.5 detection framework`
**Description:** Implement detection rules for all 5 subsets of the Arcanum taxonomy:
- Agent Manipulation (unauthorized API calls, code eval, DB lookups)
- Indirect Prompt Injection (email/doc/image-embedded payloads)
- Ecosystem Attacks (SSRF, BXSS mediated through models)
- Data Layer Attacks (PII exposure, RAG poisoning, memory corruption)
- Model Safety (jailbreaks, prompt secret extraction)

**Implementation:**
- New module: `src/arcanum_taxonomy_scanner.py`
- Pattern library: `configs/arcanum_patterns.json`
- Test suite: `tests/test_arcanum_detection.py`
- Detection target: 90%+ for each subset

#### 2. sec-context Anti-Pattern Integration
**Issue Title:** `feat: Integrate Arcanum sec-context AI code anti-patterns (25+ patterns)`
**Description:** Integrate the sec-context anti-pattern library as a native detection layer, prioritized by the following risk matrix:

| Priority | Pattern | Detection Method |
|----------|---------|-----------------|
| P0 | Slopsquatting/Hallucinated Dependencies | Package registry validation |
| P0 | Hardcoded Secrets | Shannon entropy + regex |
| P1 | XSS in AI-generated code | AST + taint analysis |
| P1 | SQL Injection patterns | Parameterization checking |
| P1 | Auth logic failures | Control flow analysis |
| P2 | Missing input validation | Data flow tracking |
| P2 | Command injection | Subprocess call analysis |
| P2 | Missing rate limiting | API endpoint scanning |

**Implementation:**
- Download and parse `ANTI_PATTERNS_BREADTH.md` (~65K tokens)
- Map each anti-pattern to scanner detection rules
- Include BAD/GOOD code examples for context-aware detection
- New module: `src/sec_context_scanner.py`

#### 3. TOCTOU + Pipeline Poisoning Detection
**Issue Title:** `feat: Detect TOCTOU and poisoned pipeline execution in MCP contexts`
**Description:** Based on documented GitHub Copilot Agent attack chain:
- Detect time-of-check to time-of-use gaps in MCP tool calls
- Flag untrusted issue/PR content processed by AI agents
- Monitor for pipeline execution triggered by external inputs
- Alert on secrets accessible during CI/CD runs

### MEDIUM PRIORITY

#### 4. Garak Integration for Model Red Teaming
**Issue Title:** `feat: Add NVIDIA Garak integration for LLM vulnerability probing`
**Description:** Integrate Garak's 40+ probe modules as an optional scanning layer:
- Hallucination detection
- Data leakage probes
- Prompt injection resistance testing
- Misinformation generation detection
- Pre-deployment security baseline establishment

**Implementation:**
- New module: `src/integrations/garak_bridge.py`
- CLI flag: `--red-team` to enable model probing
- Output format: Compatible with existing scan report schema

#### 5. PyRIT Multi-Turn Attack Simulation
**Issue Title:** `feat: Add Microsoft PyRIT integration for adversarial simulation`
**Description:** Integrate PyRIT for multi-turn attack orchestration:
- Simulate persistent adversarial interactions
- Test guardrail effectiveness (Vigil LLM compatibility)
- Bridge with traditional pentest workflows via PyRIT SHIP
- Generate adversarial test cases automatically

#### 6. Certificate Transparency Log Monitoring
**Issue Title:** `feat: Add CT log monitoring for Shadow IT discovery`
**Description:** Implement automated monitoring of public CT logs:
- Query for organization domain patterns
- Flag keywords: "git", "backup", "logging", "staging", "dev"
- Cross-reference discovered hosts against known asset inventory
- Alert on unauthenticated admin panels (Kibana, Elasticsearch, Solr)
- Estimated discoverable hosts: ~30M via keyword probing

### LOW PRIORITY

#### 7. Hallucination Rate Context Engine
**Issue Title:** `feat: Add hallucination-aware confidence scoring`
**Description:** Adjust scan confidence based on model hallucination data:
- Mistral-7B: 81.19% hallucination rate → lower confidence threshold
- GPT-4o: 45.15% → moderate confidence threshold  
- Llama-3.1-70B: 37.30% → higher confidence threshold
- Domain-specific adjustment: Math/technical = 60% hallu rate
- Require 10+ input-output examples for context engineering

---

## Unified Security Scanner Enhancements

### HIGH PRIORITY

#### 8. AI-Generated Code Detection Layer
**Issue Title:** `feat: Add AI-generated code identification and enhanced scanning`
**Description:** Detect vibe-coded files and apply enhanced scrutiny:
- Identify AI generation signatures (comment patterns, structure)
- Apply sec-context anti-patterns with stricter thresholds
- Flag the "comprehension gap" — code complexity vs. commit author experience
- Track hallucinated dependency suggestions (5-21% of AI suggestions)

#### 9. Nuclei Template Auto-Generation
**Issue Title:** `feat: AI-powered Nuclei template generation for new CVEs`
**Description:** Automate creation of Nuclei YAML templates:
- Input: CVE description or vulnerability narrative
- Output: Multi-request Nuclei template with matchers/extractors
- Validation: Test against known vulnerable and patched targets
- Integration: Auto-push to custom template repository
- Speed target: ~30 seconds per template (vs. 2-4 hours manual)

**Implementation:**
- New module: `src/nuclei_generator.py`
- Template library: `templates/generated/`
- CI/CD hook: Auto-generate on new CVE feed entries
- Leverage curated template repository as few-shot examples

#### 10. Multi-Agent Security Review Loop
**Issue Title:** `feat: Implement multi-agent security review pipeline`
**Description:** Build a multi-layer validation pipeline:
- Layer 1: AI-powered initial review (sec-context reference)
- Layer 2: Semgrep deterministic SAST validation
- Layer 3: Gitleaks credential scanning
- Layer 4: "Ghost rule" detection — patterns AI claimed to apply but didn't
- Layer 5: Human review queue for high-severity findings

### MEDIUM PRIORITY

#### 11. SARIF Output for GitHub Code Scanning Integration
**Issue Title:** `feat: Add SARIF output format for GitHub Advanced Security integration`
**Description:** Generate SARIF (Static Analysis Results Interchange Format) output:
- Compatible with GitHub Code Scanning alerts
- Display findings directly in repository Security tab
- Support for CodeQL result correlation
- Third-party tool result aggregation

#### 12. Red/Blue/Purple Team Workflow Templates
**Issue Title:** `feat: Add operational workflow templates for security teams`
**Description:** Based on Arcanum's Red Blue Purple AI methodology:

**Red Team Templates:**
- Custom GPT recon agents (Subdomain Doctor, Acquisition Recon)
- Gradient-based injection fuzzing configurations
- AI-powered phishing material generation
- EDR bypass scanning templates

**Blue Team Templates:**
- Suricata/Yara/OSQuery/Semgrep rule generation
- SOC incident coordination bot configurations
- ASM subdomain enumeration for vibe-coded Shadow IT
- Chatbot log monitoring for data leakage

**Purple Team Templates:**
- Adversarial emulation scenarios (PyRIT configs)
- Tabletop exercise generators for AI-specific threats
- Bug bounty → Nuclei template feedback loop automation

---

## Shared Infrastructure Enhancements

#### 13. Unified Configuration Schema
**Issue Title:** `chore: Unified config schema across both scanners`
- Shared anti-pattern definitions
- Common severity scoring (aligned with CVSS + AI-specific metrics)
- Cross-repo detection rule synchronization
- Shared Nuclei template repository

#### 14. GitHub Actions Workflow Templates
**Issue Title:** `feat: Pre-built GitHub Actions for both scanners`
- One-click CI/CD integration
- Matrix testing across multiple language targets
- Automated SARIF upload to GitHub Security
- Scheduled scanning with configurable frequency
- Dependency verification (anti-slopsquatting) on every PR

#### 15. Documentation Overhaul
**Issue Title:** `docs: Research-backed documentation update`
- Map each detection rule to Arcanum taxonomy subset
- Include real-world attack chain examples
- Add decision trees for scan configuration
- Publish benchmark data: detection rates, false positive rates, scan speeds

---

## Implementation Timeline

| Phase | Timeframe | Items | Focus |
|-------|-----------|-------|-------|
| Phase 1 | Week 1-2 | #1, #2, #8 | Core detection framework |
| Phase 2 | Week 3-4 | #3, #9, #10 | Pipeline integration |
| Phase 3 | Month 2 | #4, #5, #11 | Red team tooling |
| Phase 4 | Month 3 | #6, #7, #12 | Advanced capabilities |
| Ongoing | Continuous | #13, #14, #15 | Infrastructure & docs |

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Detection Rate (MCP-specific) | 95% | 98% |
| False Positive Rate | 0% | 0% |
| Anti-Pattern Coverage | ~10 patterns | 25+ patterns |
| Scan Speed | 1,400 files/sec | 2,000 files/sec |
| Arcanum Taxonomy Coverage | 0/5 subsets | 5/5 subsets |
| Nuclei Template Generation | Manual | <30 sec automated |
| SARIF Integration | No | Yes |
| CT Log Monitoring | No | Yes |

---

*This enhancement plan directly supports the SecurityLeader.ai thought leadership platform and positions both repositories as reference implementations for AI-era security scanning.*
