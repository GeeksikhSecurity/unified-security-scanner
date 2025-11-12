# Claude Custom Rules for Documentation Excellence

**Version:** 1.0
**Last Updated:** November 11, 2025
**Framework:** Ogawa Coffee-Inspired Documentation Methodology
**Project:** [GeeksikhSecurity](https://github.com/GeeksikhSecurity)

---

## Philosophy

_"The best documentation is invisible—users accomplish their goals without realizing they consulted it."_

---

## Executive Summary

This framework establishes technical documentation standards that transform complex information into intuitive, user-friendly content. Inspired by the clarity and completeness of Ogawa Coffee's FAQ system (https://www.oc-ogawa.co.jp/contact/faq/) and the podcast episode "From Knowledge to Wisdom" by Luca Rossi, this approach ensures documentation works like a well-designed product—providing everything users need, with nothing missing.

**Core Principle:** _"A documentation set should be like a complete gift - everything needed with no missing pieces"_

---

## Overview

This project uses the **Ogawa Coffee-Inspired Documentation Framework** to create complete, user-centric documentation that transforms basic reference material into comprehensive learning experiences.

All documentation work in this project MUST follow these principles.

---

## Core Principles

### 1. The "Complete Gift" Philosophy

Every piece of documentation should be a **complete gift** to the reader - nothing missing, all questions answered.

**Implementation:**
- Answer questions users haven't asked yet (anticipatory design)
- Provide multiple learning modes (text, diagrams, examples, tables)
- Include context-aware warnings without being patronizing
- Every section has: Direct answer → Rationale → Related info → Next steps

### 2. Four Facets Framework

All documentation MUST cover these four facets:

#### ✅ Data (The "What")
- Commands, syntax, specifications
- Configuration options and values
- Version requirements and constraints
- Performance numbers and benchmarks

#### ✅ Structure (The "How")
- Step-by-step progressions with numbering
- Verification checklists with checkboxes
- Decision matrices for comparisons
- Hierarchical organization

#### ✅ Meaning (The "Which")
- Glossary-style definitions inline
- Examples showing practical usage
- Clarifications of technical terms
- Comparisons of similar concepts

#### ✅ Context (The "Why, Where, Who, When")
- Why each step matters
- When to use specific patterns
- Who should use which approach
- Where to find additional help

### 3. Knowledge → Skills → Wisdom Progression

Structure documentation to guide users through three learning levels:

**Level 1: Knowledge (Information Transfer)**
- What: Commands, syntax, configuration
- User can: Repeat facts, follow instructions
- Format: Direct statements, numbered steps

**Level 2: Skills (Practical Application)**
- What: Running tasks, interpreting results, troubleshooting
- User can: Execute tasks, handle problems
- Format: Examples, checklists, common issues

**Level 3: Wisdom (Context-Aware Judgment)**
- What: When to use patterns, how to choose approaches
- User can: Make informed decisions in novel situations
- Format: Decision matrices, role-based paths, trade-off analysis

---

## Documentation Standards

### Required Metadata for Guides

Every guide MUST start with:

```markdown
# [Guide Title]

**Time to complete:** [X-Y minutes]
**Difficulty:** [Beginner|Intermediate|Advanced]
**Last updated:** [YYYY-MM-DD]
**Prerequisites:** [List of required knowledge/tools]

## What You'll Accomplish

[Clear learning outcomes in 2-3 bullet points]

**You'll learn:**

- ✅ [Knowledge-level outcome]
- ✅ [Skills-level outcome]
- ✅ [Wisdom-level outcome]
```

### Section Structure Template

Each major section should follow this pattern:

```markdown
## [Section Title]

### [Subsection - What this does]

**Why this matters:** [Context and importance]

[Main content with examples]

**Expected result:** [What success looks like]

**Common issues:**
- **"[Error message]"** → [Solution]

**Why this works:** [Explanation of underlying mechanism]

**Next steps:** [Where to go from here]
```

### Prerequisites Pattern

Always provide context for requirements:

```markdown
## Prerequisites

Before starting, ensure you have:

- [ ] **[Tool/Knowledge]** ([Link]) - [Purpose]
  - **Why:** [Reason it's needed]
  - **Check:** Run `[verification command]` (should show [expected output])
```

### Troubleshooting FAQ Pattern

Use Ogawa Coffee FAQ methodology:

```markdown
### Q. [User's natural question in their words]

**Category:** [Installation|Configuration|Performance|Integration]
**Applies to:** [Scope - which versions/environments]

**A. [Direct answer first - one clear sentence]**

**Why this happens:** [Root cause explanation]

**Solution:**

[Step-by-step fix with commands]

**Why this works:** [Explanation of solution]

**Still stuck?** [Escalation path - where to get help]

**Related:** [Links to related troubleshooting entries]
```

### Decision Matrix Pattern

Help users make context-aware choices:

```markdown
### [Decision Name] Guide

| Option | Use Case | Best For | Trade-offs |
|--------|----------|----------|------------|
| **[Option 1]** | [Scenario] | [User type] | [Pros/Cons] |
| **[Option 2]** | [Scenario] | [User type] | [Pros/Cons] |

**Rule of thumb:**
- **[Context 1]:** Use [Option]
- **[Context 2]:** Use [Option]
```

### Role-Based Learning Paths

Provide different paths for different user contexts:

```markdown
## What's Next? Your Learning Path

### Path 1: [User Role] ([Goal])

**Immediate actions:**

1. **[Task 1]**
   ```bash
   [command]
   ```

2. **[Task 2]** ([why this matters])

3. **[Task 3]**

**Next:** [Link to advanced guide for this path]

---

### Path 2: [Different User Role] ([Different Goal])

[Same structure]
```

---

## Visual Documentation Standards

### ASCII Diagrams

Use ASCII art for architecture and flow diagrams:

```markdown
### [Diagram Title]

\```text
┌─────────────────────────────────────────────┐
│         Component Name                      │
├─────────────────────────────────────────────┤
│  - Responsibility 1                         │
│  - Responsibility 2                         │
└────────────┬────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────┐
│         Next Component                      │
└─────────────────────────────────────────────┘
\```

**Flow explanation:**
1. [Step 1 description]
2. [Step 2 description]
```

### Sequence Diagrams

For interaction flows:

```markdown
\```text
User          CLI           Core          Adapter        Tool
  │            │             │              │             │
  ├───[cmd]───>│             │              │             │
  │            ├──[init]────>│              │             │
  │            │             ├──[execute]──>│             │
  │            │             │              ├──[run]─────>│
  │            │             │              │<────[out]───┤
  │            │             │<──[results]──┤             │
  │<──[output]─┤             │              │             │
\```
```

---

## When to Apply This Framework

### Apply Full Framework For:

- ✅ User-facing documentation (Quick Start, tutorials, guides)
- ✅ Architecture documentation (system design, data flows)
- ✅ API documentation (endpoints, SDKs, integration guides)
- ✅ Troubleshooting guides (FAQ, common issues)
- ✅ Configuration references (all options explained)

### Lighter Application For:

- ⚠️ Code comments (apply Context facet - explain why)
- ⚠️ Changelogs (apply Structure facet - categorize changes)
- ⚠️ README files (apply all facets but more concisely)

### Not Required For:

- ❌ Auto-generated API docs (unless adding examples)
- ❌ License files, legal documents
- ❌ Build artifacts, generated files

---

## Documentation Enhancement Checklist

When creating or enhancing documentation, verify:

### Four Facets Coverage

- [ ] **Data**: All commands, options, and specifications documented
- [ ] **Structure**: Clear hierarchy, numbered steps, decision matrices
- [ ] **Meaning**: Technical terms defined, examples provided
- [ ] **Context**: Why/when/who/where questions answered

### Learning Progression

- [ ] **Knowledge**: Basic facts and syntax included
- [ ] **Skills**: Practical examples and troubleshooting provided
- [ ] **Wisdom**: Decision guidance and role-based paths included

### Ogawa Coffee Principles

- [ ] **Anticipatory**: FAQ answers unasked questions
- [ ] **Multi-Modal**: Text + diagrams + examples + tables
- [ ] **Safe**: Warnings are contextual, not scary
- [ ] **Complete**: No loose ends, all paths lead somewhere

### Quality Metrics

- [ ] **Time estimate**: Provided for guides (5-10 min, 30 min, etc.)
- [ ] **Difficulty level**: Clearly marked (Beginner/Intermediate/Advanced)
- [ ] **Success criteria**: "What success looks like" included
- [ ] **Common issues**: At least 3-5 anticipated problems addressed
- [ ] **Next steps**: Clear guidance on what to do after

---

## Implementation Commands

When Claude is asked to enhance documentation, follow this process:

### 1. Analysis Phase

```markdown
1. Read the existing documentation
2. Assess current coverage using Four Facets Framework:
   - Data: __% complete
   - Structure: __% complete
   - Meaning: __% complete
   - Context: __% complete
3. Calculate Documentation Health Score: __/100
4. Identify user personas and their journeys
5. List gaps and opportunities
```

### 2. Enhancement Phase

```markdown
1. Add metadata header (time, difficulty, outcomes)
2. Enhance each section with Four Facets:
   - Add "Why this matters" context
   - Add "Expected result" verification
   - Add "Common issues" troubleshooting
   - Add "Why this works" explanations
3. Create or enhance FAQ with anticipatory questions
4. Add decision matrices where users must choose
5. Create role-based learning paths
6. Add visual diagrams for complex flows
```

### 3. Validation Phase

```markdown
1. Run through Documentation Enhancement Checklist
2. Verify all facets have >80% coverage
3. Test that a user can complete tasks without external help
4. Check for "dead ends" - sections without next steps
5. Calculate new Documentation Health Score (target: >90/100)
```

### 4. Commit Phase

When committing documentation enhancements:

```bash
# Use this commit message template
git commit -m "docs: [Enhancement type] using Ogawa Coffee methodology

[Brief description of what was enhanced]

## Philosophy

\"The best documentation is invisible—users accomplish their goals
without realizing they consulted it.\"

## Enhancements

- **Four Facets**: [Data|Structure|Meaning|Context improvements]
- **Learning Progression**: [Knowledge|Skills|Wisdom additions]
- **Anticipatory Design**: [FAQ entries, decision matrices added]

## Impact

- Documentation Health Score: [before] → [after]
- User coverage: [what user journeys now supported]
- Completeness: [what gaps were filled]

## Framework Applied

Based on Ogawa Coffee FAQ excellence and \"From Knowledge to Wisdom\":
- https://www.oc-ogawa.co.jp/contact/faq/
- Luca Rossi's Knowledge → Skills → Wisdom framework

Project: https://github.com/GeeksikhSecurity

🤖 Generated with Claude Code (https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Examples and Reference

### Example: Basic Reference → Complete Guide

**Before (Basic Reference):**
```markdown
## Installation

\```bash
npm install security-scanner
\```
```

**After (Complete Guide):**
```markdown
## 🚀 Installation

### Step 1: Install the Package

**Why this step matters:** Installing the package gives you access to all security scanning tools and their latest security rules.

\```bash
# Install via npm (takes ~30 seconds)
npm install -g security-scanner

# Verify installation
security-scanner --version
\```

**Expected result:** You should see version 1.0.0 or higher.

**Common issues:**

- **"Permission denied"** → Use `sudo npm install -g` or fix npm permissions
- **"Command not found"** → Add npm global bin to PATH: `export PATH=$PATH:$(npm bin -g)`

**Why this works:** The `-g` flag installs globally, making the `security-scanner` command available system-wide.

**Next steps:** Continue to [Your First Scan](#your-first-scan) to verify the installation.
```

### Example: Command List → Wisdom-Level Patterns

**Before (Command List):**
```markdown
## Commands

- `scan .` - Scan current directory
- `scan --format=json` - Output JSON
- `scan --fail-on=critical` - Fail on critical issues
```

**After (Wisdom-Level Patterns):**
```markdown
## 📋 Common Scan Patterns (Wisdom Level)

Now that you can run scans, here's **when** and **how** to use different configurations based on your context.

### Pattern 1: Local Development Workflow

**Use case:** Quick checks before committing code

\```bash
scan . --fail-on=critical
\```

**When to use:**
- ✅ Before `git commit` (catch secrets early)
- ✅ After adding new dependencies
- ✅ When working with sensitive data

**Why it works:** Fast feedback loop, catches critical issues before they enter version control.

**Trade-off:** Won't catch medium/low issues until CI/CD runs.

---

### Pattern 2: CI/CD Pipeline Integration

**Use case:** Automated security gates in GitHub Actions

\```bash
scan . --format=sarif,terminal --output=./reports --fail-on=critical,high
\```

**When to use:**
- ✅ Pull request validation (block merges on critical/high)
- ✅ Nightly security audits (all severities)
- ✅ Pre-deployment checks (production releases)

**Why SARIF format:** Integrates with GitHub Security tab, shows inline annotations in PRs.

---

### Decision Matrix: Fail-On Strategy

| Setting | Use Case | Exit Code Behavior |
|---------|----------|-------------------|
| `--fail-on=critical` | Development branches | Only critical = fail |
| `--fail-on=critical,high` | Production merges | Critical or High = fail |
| No `--fail-on` | Monitoring only | Always succeed (0) |

**Rule of thumb:**
- **Local dev:** No `--fail-on` (warnings only)
- **Feature branches:** `--fail-on=critical`
- **Main/master:** `--fail-on=critical,high`
```

---

## Project-Specific Customization

For this security scanner project:

### Documentation Priority Order

1. **User onboarding** (Quick Start) - HIGHEST priority
2. **Architecture** (system understanding) - HIGH priority
3. **Configuration** (customization) - MEDIUM priority
4. **API reference** (programmatic usage) - MEDIUM priority
5. **Contributing** (developer onboarding) - LOW priority

### Security-Specific Context

Always include security context:
- **Risk level**: What could go wrong if misconfigured
- **Compliance**: SOC 2, PCI-DSS, GDPR implications
- **Best practices**: OWASP, CWE references
- **Real-world examples**: Actual vulnerability scenarios

### Performance Considerations

Include performance context:
- **Benchmarks**: Small/medium/large project timings
- **Optimization**: Impact/effort matrix for improvements
- **Trade-offs**: Speed vs comprehensiveness

---

## Continuous Improvement

### Documentation Health Tracking

Track these metrics in documentation commits:

```markdown
## Documentation Health Score

**Before:** __/100
**After:** __/100
**Improvement:** +__%

**Facet Breakdown:**
- Data: __/25 → __/25
- Structure: __/25 → __/25
- Meaning: __/25 → __/25
- Context: __/25 → __/25

**Predicted Impact:**
- Time to first success: __ → __ minutes
- Support ticket reduction: __%
- Task completion rate: __%
```

### User Feedback Integration

When users report documentation issues:

1. **Classify the gap**: Which facet was missing? (Data/Structure/Meaning/Context)
2. **Update the FAQ**: Add anticipatory question
3. **Enhance context**: Add "Why this happens" explanation
4. **Add to decision matrix**: If it's a choice between options

---

## References

### Primary Frameworks

1. **Ogawa Coffee FAQ Excellence**
   - URL: https://www.oc-ogawa.co.jp/contact/faq/
   - Principle: Complete Gift - Nothing Missing
   - Application: Anticipatory FAQ, multi-modal explanations

2. **Skiller Whale Training Methodology**
   - Framework: Knowledge → Skills → Wisdom
   - Application: Progressive learning paths, role-based guidance

3. **Technical Documentation Standards Framework**
   - Author: G.S. | Cybersecurity & Documentation Specialist
   - Framework: Four Facets (Data, Structure, Meaning, Context)
   - Application: Complete documentation architecture

### Supporting Resources

- Google Developer Documentation Style Guide
- Microsoft Writing Style Guide
- *Docs for Developers* by Jared Bhatti et al.
- *Every Page is Page One* by Mark Baker

---

## Quick Reference for Claude

When asked to enhance documentation:

1. ✅ Read existing docs and calculate health score
2. ✅ Apply Four Facets Framework systematically
3. ✅ Add Knowledge → Skills → Wisdom progression
4. ✅ Create anticipatory FAQ entries
5. ✅ Add decision matrices for choices
6. ✅ Include role-based learning paths
7. ✅ Add visual diagrams for complex flows
8. ✅ Verify with Documentation Enhancement Checklist
9. ✅ Calculate new health score (target >90/100)
10. ✅ Commit with framework-based message

**Target Outcome:** Users can complete their tasks without external help, understanding not just "how" but "why" and "when."

---

**Maintained by:** Security Scanner Documentation Team
**Questions?** See [DOCUMENTATION_COMMIT_SUMMARY.md](../docs/DOCUMENTATION_COMMIT_SUMMARY.md) for implementation examples
