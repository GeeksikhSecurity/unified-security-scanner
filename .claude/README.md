# Claude Configuration for Security Scanner Project

This directory contains custom rules, prompts, and settings for Claude Code to ensure consistent, high-quality documentation following the **Ogawa Coffee-Inspired Documentation Framework**.

---

## Files in This Directory

### [claude.md](claude.md)
**Purpose:** Custom rules defining documentation standards for this project

**What it contains:**
- The "Complete Gift" philosophy
- Four Facets Framework (Data, Structure, Meaning, Context)
- Knowledge → Skills → Wisdom progression methodology
- Documentation templates and patterns
- Quality checklists and metrics

**When Claude uses it:** Automatically loaded for all sessions in this project

### [prompts/enhance-documentation.md](prompts/enhance-documentation.md)
**Purpose:** Step-by-step prompt for documentation enhancement tasks

**What it contains:**
- Analysis phase (assess current state)
- Enhancement plan template
- Execution steps with examples
- Validation checklist
- Summary report format

**How to use it:**
```
/enhance-documentation <filename>
```

### [settings.local.json](settings.local.json)
**Purpose:** Project-specific permissions and configurations

**What it contains:**
- Pre-approved git commands for documentation commits
- Custom commit message templates
- Tool permissions

---

## Quick Start

### For Documentation Enhancement

1. **Analyze existing documentation:**
   ```
   Claude, analyze docs/EXAMPLE.md using the documentation framework
   ```

2. **Enhance a document:**
   ```
   Claude, enhance docs/EXAMPLE.md following the Ogawa Coffee methodology
   ```

3. **Create new documentation:**
   ```
   Claude, create a new guide for [topic] using our documentation standards
   ```

### For Commit Messages

The pre-approved commit message template follows this format:

```
docs: [Enhancement type] using Ogawa Coffee methodology

[Brief description]

## Enhancements

- **Four Facets**: [improvements]
- **Learning Progression**: [additions]
- **Anticipatory Design**: [FAQ, matrices added]

## Impact

- Documentation Health Score: [before] → [after]
- User coverage: [journeys supported]

## Framework Applied

Based on Ogawa Coffee FAQ excellence:
https://www.oc-ogawa.co.jp/contact/faq/

🤖 Generated with Claude Code (https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## Documentation Standards Summary

### Every Guide Must Have

✅ **Metadata header** (time, difficulty, last updated)
✅ **Learning outcomes** (Knowledge → Skills → Wisdom)
✅ **Prerequisites with context** (why needed, how to verify)
✅ **"Why this matters"** for each major section
✅ **Expected results** and success criteria
✅ **Common issues** with solutions
✅ **Troubleshooting FAQ** (anticipatory)
✅ **Role-based next steps** (where to go from here)

### Four Facets Coverage Required

| Facet | What to Include | Target |
|-------|-----------------|--------|
| **Data** | Commands, specs, benchmarks | >80% |
| **Structure** | Steps, checklists, matrices | >80% |
| **Meaning** | Definitions, examples, comparisons | >80% |
| **Context** | Why, when, who, where | >80% |

### Target Metrics

- **Documentation Health Score:** >90/100
- **Time to first success:** <10 minutes for Quick Starts
- **Support ticket reduction:** -40% target
- **Task completion rate:** >85% target

---

## Framework Principles

### The "Complete Gift" Philosophy

Every piece of documentation should be a **complete gift** - nothing missing:

1. **Anticipatory Completeness** - Answer questions users haven't asked yet
2. **Multi-Modal Learning** - Text + diagrams + examples + tables
3. **Safety Without Patronizing** - Context-aware warnings
4. **Nothing Missing** - Every section has: answer + rationale + next steps

### Knowledge → Skills → Wisdom

Structure content in three levels:

- **Level 1 (Knowledge):** Commands, syntax → User can repeat facts
- **Level 2 (Skills):** Examples, troubleshooting → User can execute tasks
- **Level 3 (Wisdom):** Decision matrices, role paths → User can choose wisely

### Four Facets Framework

All documentation covers:

- **Data:** What (commands, specs, numbers)
- **Structure:** How (steps, hierarchy, organization)
- **Meaning:** Which (definitions, examples, clarifications)
- **Context:** Why/When/Who/Where (rationale, timing, audience, location)

---

## Examples

### Bad Documentation (Before)

```markdown
## Installation

\```bash
npm install security-scanner
\```
```

**Issues:**
- ❌ No context (why)
- ❌ No verification (success criteria)
- ❌ No troubleshooting (common issues)
- ❌ No next steps (where to go)

### Good Documentation (After)

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
- **"Command not found"** → Add npm global bin to PATH

**Why this works:** The `-g` flag installs globally, making the command available system-wide.

**Next steps:** Continue to [Your First Scan](#your-first-scan) to verify the installation.
```

**Improvements:**
- ✅ Context provided (why this matters)
- ✅ Success criteria clear (expected result)
- ✅ Troubleshooting included (common issues)
- ✅ Next steps explicit (where to go)

---

## Usage Patterns

### Pattern 1: Quick Enhancement

**User request:**
> "Add troubleshooting section to README.md"

**Claude response:**
1. Reads README.md
2. Applies FAQ methodology from claude.md
3. Creates 5-8 anticipatory Q&A entries
4. Each follows: Question → Answer → Why → Solution → Why it works → Still stuck?

### Pattern 2: Complete Transformation

**User request:**
> "Transform this basic guide into an Ogawa Coffee-level experience"

**Claude response:**
1. Analyzes current state (Four Facets assessment)
2. Calculates Documentation Health Score
3. Creates enhancement plan
4. Applies all principles systematically
5. Validates with checklist
6. Provides before/after metrics

### Pattern 3: New Documentation

**User request:**
> "Create a deployment guide"

**Claude response:**
1. Uses templates from claude.md
2. Structures with Knowledge → Skills → Wisdom
3. Includes all required sections
4. Adds role-based paths (DevOps, SRE, Developer)
5. Creates decision matrices (deployment options)
6. Adds visual diagrams (architecture)

---

## Customization

### For Other Projects

To use this framework in other projects:

1. **Copy the framework files:**
   ```bash
   cp -r .claude/ /path/to/other/project/
   ```

2. **Customize claude.md:**
   - Update project-specific context
   - Adjust documentation priorities
   - Add domain-specific patterns

3. **Update settings.local.json:**
   - Modify commit message template
   - Add project-specific permissions

### For Different Documentation Types

- **API docs:** Emphasize examples for every endpoint
- **Architecture docs:** Emphasize visual diagrams
- **Tutorials:** Emphasize hands-on practice
- **Reference:** Emphasize completeness and searchability

---

## Quality Assurance

### Before Committing Documentation

Run this checklist:

```markdown
## Documentation Enhancement Checklist

### Four Facets Coverage
- [ ] Data: Commands, specs, benchmarks documented
- [ ] Structure: Clear hierarchy, steps, checklists
- [ ] Meaning: Terms defined, examples provided
- [ ] Context: Why/when/who/where answered

### Learning Progression
- [ ] Knowledge: Basic facts included
- [ ] Skills: Practical examples provided
- [ ] Wisdom: Decision guidance added

### Ogawa Coffee Principles
- [ ] Anticipatory: FAQ with unasked questions
- [ ] Multi-Modal: Text + diagrams + examples
- [ ] Safe: Contextual warnings included
- [ ] Complete: No dead ends

### Quality Metrics
- [ ] Time estimate provided
- [ ] Difficulty level marked
- [ ] Success criteria clear
- [ ] Common issues addressed (5+)
- [ ] Next steps explicit

### Documentation Health Score: __/100
Target: >90/100
```

---

## References

### Primary Inspirations

1. **Ogawa Coffee FAQ**
   - URL: https://www.oc-ogawa.co.jp/contact/faq/
   - Excellence: Anticipatory design, complete answers

2. **Skiller Whale Training**
   - Framework: Knowledge → Skills → Wisdom
   - Excellence: Granular assessment, context-aware teaching

3. **Technical Documentation Standards**
   - Framework: Four Facets (Data, Structure, Meaning, Context)
   - Excellence: Complete coverage methodology

### Example Documentation

See these files for framework application examples:

- [QUICK_START.md](../QUICK_START.md) - Complete learning experience (964 lines)
- [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) - Visual system documentation (1,533 lines)
- [docs/QUICK_START_ENHANCEMENT_SUMMARY.md](../docs/QUICK_START_ENHANCEMENT_SUMMARY.md) - Methodology explanation

---

## Getting Help

### Documentation Issues

If documentation doesn't meet standards:

1. **Assess the gap:** Which facet is missing? (Data/Structure/Meaning/Context)
2. **Check claude.md:** Find the relevant template or pattern
3. **Apply systematically:** Use the enhancement checklist
4. **Validate:** Run through quality metrics

### Claude Behavior Issues

If Claude isn't following the framework:

1. **Reference claude.md explicitly:**
   ```
   Claude, apply the principles from .claude/claude.md to enhance this doc
   ```

2. **Use the enhancement prompt:**
   ```
   Follow the process in .claude/prompts/enhance-documentation.md
   ```

3. **Provide examples:**
   ```
   Enhance this section like you did in QUICK_START.md lines 73-140
   ```

---

## Continuous Improvement

### Updating the Framework

When you discover new patterns or improvements:

1. **Document in claude.md:** Add to relevant section
2. **Create example:** Show before/after
3. **Update checklist:** Add validation item
4. **Share learning:** Update this README

### Measuring Impact

Track these metrics over time:

- **Documentation Health Scores** (target: all >90/100)
- **Support ticket trends** (target: -40% reduction)
- **User feedback** (target: 8+/10 satisfaction)
- **Time to first success** (target: <10 min for guides)

---

**Maintained by:** Security Scanner Documentation Team
**Questions?** See [DOCUMENTATION_COMMIT_SUMMARY.md](../docs/DOCUMENTATION_COMMIT_SUMMARY.md)
**Framework Version:** 1.0
**Last Updated:** November 11, 2025
