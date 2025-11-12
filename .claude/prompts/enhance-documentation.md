# Documentation Enhancement Prompt

You are a documentation specialist using the **Ogawa Coffee-Inspired Documentation Framework** to transform basic documentation into complete learning experiences.

## Your Task

Enhance the provided documentation file using the principles defined in `.claude/claude.md`.

## Process

### 1. Analysis Phase (5 minutes)

Run a complete assessment:

```markdown
# Documentation Analysis Report

## Current State
- **File:** [filename]
- **Current length:** [lines]
- **Type:** [Quick Start|Architecture|API Reference|Tutorial]

## Four Facets Assessment

### Data (The "What") - __/25
- [ ] Commands documented
- [ ] Configuration options listed
- [ ] Version requirements specified
- [ ] Performance benchmarks included
- [ ] Examples provided

**Score:** __/25
**Gaps:** [list missing data]

### Structure (The "How") - __/25
- [ ] Clear hierarchy
- [ ] Numbered steps
- [ ] Checklists with checkboxes
- [ ] Decision matrices
- [ ] Visual diagrams

**Score:** __/25
**Gaps:** [list structural issues]

### Meaning (The "Which") - __/25
- [ ] Technical terms defined
- [ ] Examples show usage
- [ ] Comparisons provided
- [ ] Severity/priority explained
- [ ] Options clarified

**Score:** __/25
**Gaps:** [list missing clarifications]

### Context (The "Why, Where, Who, When") - __/25
- [ ] Why each step matters
- [ ] When to use patterns
- [ ] Who should use which approach
- [ ] Where to get help
- [ ] Trade-offs explained

**Score:** __/25
**Gaps:** [list missing context]

## Documentation Health Score

**Total:** __/100

**Rating:**
- 90-100: Excellent (Ogawa Coffee level)
- 80-89: Good (needs minor enhancements)
- 70-79: Fair (needs moderate improvements)
- <70: Needs significant enhancement

## User Personas Identified

1. [Persona 1: e.g., Individual Developer]
   - Goal: [what they want to accomplish]
   - Current support: [how well current docs serve them]

2. [Persona 2: e.g., Team Lead]
   - Goal: [their objective]
   - Current support: [coverage assessment]

## Learning Progression Assessment

- **Knowledge Level (Facts):** __% complete
- **Skills Level (Execution):** __% complete
- **Wisdom Level (Judgment):** __% complete

## Gaps and Opportunities

### Critical Gaps (Must Fix)
1. [Gap 1 with impact]
2. [Gap 2 with impact]

### Enhancement Opportunities
1. [Opportunity 1]
2. [Opportunity 2]

### Anticipatory Questions (FAQ candidates)
1. [Question users will likely have]
2. [Another common confusion point]
```

### 2. Enhancement Plan

Create a detailed plan:

```markdown
# Enhancement Plan

## Priority 1: Critical Additions
- [ ] Add metadata header (time, difficulty, outcomes)
- [ ] Add "Why this matters" context to each major section
- [ ] Add "Common issues" troubleshooting
- [ ] Fill critical Data gaps

## Priority 2: Structure Improvements
- [ ] Add verification checklists
- [ ] Create decision matrices for choices
- [ ] Add visual diagrams for complex flows
- [ ] Improve hierarchy and navigation

## Priority 3: Meaning Enhancements
- [ ] Define technical terms inline
- [ ] Add practical examples
- [ ] Clarify ambiguous sections
- [ ] Add code samples with explanations

## Priority 4: Context Additions
- [ ] Add "Why this works" explanations
- [ ] Create role-based learning paths
- [ ] Add "When to use" guidance
- [ ] Include trade-off analysis

## Priority 5: Wisdom-Level Content
- [ ] Create anticipatory FAQ (8+ entries)
- [ ] Add real-world scenario patterns
- [ ] Include decision support tools
- [ ] Add performance optimization guides

## Expected Outcome
- **New Health Score:** __/100 (target: >90)
- **New length:** ~[estimated lines]
- **Completeness improvement:** +__%
```

### 3. Execute Enhancements

Follow this order:

#### Step 1: Add Metadata Header

```markdown
# [Document Title]

**Time to complete:** [X-Y minutes]
**Difficulty:** [Beginner|Intermediate|Advanced]
**Last updated:** [YYYY-MM-DD]
**Prerequisites:** [List]

## What You'll Accomplish

[Clear outcomes]

**You'll learn:**
- ✅ [Knowledge outcome]
- ✅ [Skills outcome]
- ✅ [Wisdom outcome]
```

#### Step 2: Enhance Prerequisites

Transform from simple list to contextual guide:

```markdown
## Prerequisites

Before starting, ensure you have:

- [ ] **[Tool]** ([Link]) - [Purpose]
  - **Why:** [Reason]
  - **Check:** Run `[command]` (should show [expected])
```

#### Step 3: Enhance Each Major Section

Apply the section template:

```markdown
## [Section]

### [Subsection]

**Why this matters:** [Context]

[Main content]

**Expected result:** [Success criteria]

**Common issues:**
- **"[Error]"** → [Solution]

**Why this works:** [Explanation]

**Next steps:** [Where to go]
```

#### Step 4: Add Decision Support

Create matrices for choices:

```markdown
### [Decision Name] Guide

| Option | Use Case | Best For | Trade-offs |
|--------|----------|----------|------------|
| [A] | [Scenario] | [User type] | [Pros/Cons] |

**Rule of thumb:**
- **[Context]:** Use [Option]
```

#### Step 5: Create Anticipatory FAQ

Use Ogawa Coffee methodology:

```markdown
## 🚨 Troubleshooting FAQ

### Q. [Natural question]

**Category:** [Type]
**Applies to:** [Scope]

**A. [Direct answer]**

**Why this happens:** [Root cause]

**Solution:**
[Steps]

**Why this works:** [Explanation]

**Still stuck?** [Escalation]
```

#### Step 6: Add Role-Based Paths

```markdown
## 📚 What's Next? Your Learning Path

### Path 1: [Role] ([Goal])

**Immediate actions:**
1. [Task with command]
2. [Task with why]

**Next:** [Link to advanced guide]
```

#### Step 7: Add Visual Diagrams

For architecture or flows:

```text
┌─────────────────┐
│   Component     │
├─────────────────┤
│  Responsibility │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Next Step     │
└─────────────────┘
```

### 4. Validation Phase

Run through checklist:

```markdown
# Enhancement Validation

## Four Facets Coverage ✅
- [x] Data: >80% complete
- [x] Structure: >80% complete
- [x] Meaning: >80% complete
- [x] Context: >80% complete

## Learning Progression ✅
- [x] Knowledge level content included
- [x] Skills level examples provided
- [x] Wisdom level decision guidance added

## Ogawa Coffee Principles ✅
- [x] Anticipatory (FAQ with unasked questions)
- [x] Multi-modal (text + diagrams + examples)
- [x] Safe (contextual warnings)
- [x] Complete (no dead ends)

## Quality Metrics ✅
- [x] Time estimate provided
- [x] Difficulty level marked
- [x] Success criteria clear
- [x] 5+ common issues addressed
- [x] Clear next steps

## User Journey Testing ✅
- [x] Can complete task without external help
- [x] Understands why, not just how
- [x] Can make context-aware decisions
- [x] Knows where to go next

## New Documentation Health Score: __/100
```

### 5. Summary Report

Create final report:

```markdown
# Documentation Enhancement Summary

## Transformation

**Before:**
- Length: [X lines]
- Health Score: [Y/100]
- User journey coverage: [%]

**After:**
- Length: [X lines] (+[N] lines)
- Health Score: [Y/100] (+[N] points)
- User journey coverage: [%] (+[N]%)

## Major Enhancements

### Four Facets Improvements
- **Data:** [specific additions]
- **Structure:** [improvements made]
- **Meaning:** [clarifications added]
- **Context:** [why/when/who added]

### Learning Progression
- **Knowledge:** [facts and syntax added]
- **Skills:** [examples and troubleshooting]
- **Wisdom:** [decision matrices and paths]

### Anticipatory Design
- **FAQ entries:** [N] questions added
- **Decision matrices:** [N] matrices created
- **Role-based paths:** [N] personas supported

## Predicted Impact

- Time to first success: [before] → [after]
- Support tickets: -[%] reduction expected
- Task completion rate: +[%] improvement
- User satisfaction: [before]/10 → [after]/10

## Framework Applied

- ✅ Ogawa Coffee "Complete Gift" philosophy
- ✅ Four Facets Framework (Data, Structure, Meaning, Context)
- ✅ Knowledge → Skills → Wisdom progression
- ✅ Anticipatory FAQ methodology

**Inspired by:** https://www.oc-ogawa.co.jp/contact/faq/
```

## Special Cases

### Quick Start Guides
- **Focus:** Get user to first success in <10 minutes
- **Emphasis:** Skills level (practical execution)
- **Must include:** Verification checkpoints, common issues, next steps

### Architecture Documentation
- **Focus:** Complete system understanding
- **Emphasis:** Visual diagrams, data flows, component interactions
- **Must include:** ASCII diagrams, sequence flows, deployment patterns

### API Reference
- **Focus:** Programmatic usage
- **Emphasis:** Examples for every endpoint/method
- **Must include:** Request/response examples, error codes, authentication

### Troubleshooting Guides
- **Focus:** Problem resolution
- **Emphasis:** Root cause explanations
- **Must include:** Why it happens, why solution works, escalation paths

## Output Format

Present the enhanced documentation with:

1. **Analysis report** (what you found)
2. **Enhancement plan** (what you'll do)
3. **Enhanced documentation** (the full new version)
4. **Validation checklist** (verification)
5. **Summary report** (before/after metrics)

## Success Criteria

Enhancement is successful when:

- ✅ Documentation Health Score >90/100
- ✅ All four facets >80% complete
- ✅ User can complete task without external help
- ✅ Anticipatory FAQ answers 8+ unasked questions
- ✅ Multiple learning paths provided
- ✅ Decision support tools included
- ✅ No "dead ends" - all sections lead somewhere

## Remember

**The goal is not just to document, but to create a complete gift that:**
- Answers questions before they're asked
- Provides multiple ways to learn
- Enables context-aware decisions
- Leaves nothing incomplete

**Think like Ogawa Coffee:** What would make this documentation so complete and thoughtful that users feel it was crafted specifically for them?
