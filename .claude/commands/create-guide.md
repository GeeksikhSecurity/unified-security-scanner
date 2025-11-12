---
description: Create new documentation guide using Ogawa Coffee methodology
---

You are creating a new documentation guide using the **Ogawa Coffee-Inspired Documentation Framework**.

## Discovery Phase

First, gather requirements by asking:

1. **What type of guide?**
   - Quick Start (get to first success fast)
   - Tutorial (step-by-step learning)
   - How-To Guide (accomplish specific task)
   - Reference (comprehensive options)
   - Architecture (system understanding)
   - Troubleshooting (problem resolution)

2. **Who is the audience?**
   - Individual Developer
   - Team Lead
   - Security Team
   - DevOps/SRE
   - Open Source Maintainer
   - Enterprise Admin

3. **What should users accomplish?**
   - Primary goal
   - Secondary goals
   - Success criteria

4. **Time budget?**
   - Quick (5-10 min)
   - Medium (20-30 min)
   - Comprehensive (1+ hour)

## Template Selection

Based on guide type, use appropriate template:

### Quick Start Guide Template

```markdown
# [Topic] Quick Start Guide

**Time to complete:** [X-Y minutes]
**Difficulty:** Beginner
**Last updated:** [YYYY-MM-DD]
**Prerequisites:** [List minimal requirements]

## What You'll Accomplish

[Clear statement of what user will achieve]

**You'll learn:**
- ✅ [Knowledge outcome - facts/syntax]
- ✅ [Skills outcome - can execute]
- ✅ [Wisdom outcome - can choose]

---

## Prerequisites

Before starting, ensure you have:

- [ ] **[Tool/Knowledge]** ([Link]) - [Purpose]
  - **Why:** [Reason it's needed]
  - **Check:** Run `[command]` (should show [expected])

**Don't have these?** [Guidance on getting prerequisites]

---

## Step 1: [First Major Step]

**Why this matters:** [Context and importance]

\```bash
# [Command with inline comment]
[command]

# [Verification command]
[verify-command]
\```

**Expected result:** [What success looks like]

**Common issues:**
- **"[Error message]"** → [Solution]
- **"[Another error]"** → [Solution]

**Why this works:** [Explanation]

---

## Step 2: [Your First Task] (Skills Level)

**What this does:** [Clear explanation]

[Instructions with examples]

**Understanding the output:**

[Explain what user sees and what it means]

**Verify success:**
- [ ] [Success criterion 1]
- [ ] [Success criterion 2]

---

## Common Patterns (Wisdom Level)

### Pattern 1: [Use Case Name]

**Use case:** [When to use this]

\```bash
[command]
\```

**When to use:**
- ✅ [Scenario 1]
- ✅ [Scenario 2]

**Why it works:** [Rationale]

---

### Decision Matrix

| Option | Use Case | Best For | Trade-offs |
|--------|----------|----------|------------|
| [A] | [Scenario] | [User type] | [Pros/Cons] |

**Rule of thumb:**
- **[Context]:** Use [Option]

---

## Troubleshooting FAQ

### Q. [Common question in user's words]

**Category:** [Topic]
**Applies to:** [Scope]

**A. [Direct answer]**

**Why this happens:** [Root cause]

**Solution:**
\```bash
[fix commands]
\```

**Why this works:** [Explanation]

**Still stuck?** [Escalation path]

---

## What's Next? Your Learning Path

### Path 1: [User Role] ([Goal])

**Immediate actions:**
1. **[Task 1]**
   \```bash
   [command]
   \```

2. **[Task 2]** ([why this matters])

**Next:** [Link to advanced guide]

---

## Getting Help

**Documentation:**
- [Link to related docs]

**Support:**
- 🐛 Bug reports: [link]
- 💡 Feature requests: [link]
- 💬 Community: [link]

---

**Thank you for [using product/improving X]! 🎉**
```

### Architecture Guide Template

```markdown
# [System Name] Architecture

**Last updated:** [YYYY-MM-DD]
**Version:** [System version]
**Audience:** Developers, Architects, Technical Leads

## Overview

[2-3 sentence high-level description]

**This document covers:**
- ✅ High-level system architecture
- ✅ Component interactions and data flow
- ✅ Deployment architecture
- ✅ Performance characteristics
- ✅ Extension points

---

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Component Architecture](#component-architecture)
3. [Data Flow](#data-flow)
4. [Deployment Architecture](#deployment-architecture)
5. [Performance Characteristics](#performance-characteristics)
6. [Security Considerations](#security-considerations)

---

## High-Level Architecture

### System Overview

\```text
┌─────────────────────────────────────────┐
│         [Component Name]                │
├─────────────────────────────────────────┤
│  [Responsibility]                       │
└───────────┬─────────────────────────────┘
            │
            ▼
\```

**Key Components:**
- **[Component 1]:** [Purpose and responsibility]
- **[Component 2]:** [Purpose and responsibility]

**Design Principles:**
1. [Principle 1 with rationale]
2. [Principle 2 with rationale]

---

## Component Architecture

### [Component Name]

**Purpose:** [What this component does]

**Responsibilities:**
- [Responsibility 1]
- [Responsibility 2]

**Dependencies:**
- [Dependency 1] - [Why needed]
- [Dependency 2] - [Why needed]

**Interface:**

\```typescript
interface [ComponentInterface] {
  [method1](): [ReturnType];
  [method2](): [ReturnType];
}
\```

**Why this design:** [Rationale for architecture choices]

---

## Data Flow

### End-to-End Flow

\```text
[User Input] → [Component A] → [Component B] → [Component C] → [Output]
\```

**Phase 1: [Phase Name]**
1. [Step with explanation]
2. [Step with explanation]

**Phase 2: [Phase Name]**
1. [Step with explanation]

**Data transformations:**
- [Input format] → [Processing] → [Output format]

---

## Deployment Architecture

### [Environment Name]

\```text
[Deployment diagram]
\```

**Components:**
- [Component]: [Deployment details]

**Why this topology:** [Rationale]

---

## Performance Characteristics

**Benchmarks:**

| Scenario | Size | Time | Throughput |
|----------|------|------|------------|
| Small | [spec] | [time] | [ops/sec] |
| Medium | [spec] | [time] | [ops/sec] |
| Large | [spec] | [time] | [ops/sec] |

**Optimization strategies:**
1. [Strategy] - Impact: [High|Medium|Low]

---

## Extension Points

**How to extend:**
1. [Extension point 1 with example]
2. [Extension point 2 with example]

---

## References

- [Related document 1]
- [Related document 2]
```

### How-To Guide Template

```markdown
# How to [Accomplish Task]

**Time to complete:** [X-Y minutes]
**Difficulty:** [Level]
**Last updated:** [YYYY-MM-DD]

## Goal

By the end of this guide, you'll know how to [specific outcome].

**Use this guide when:**
- ✅ [Scenario 1]
- ✅ [Scenario 2]

---

## Prerequisites

- [ ] [Requirement with check command]

---

## Steps

### Step 1: [Action]

\```bash
[command]
\```

**What this does:** [Explanation]

**Verify:** [How to check success]

---

### Step 2: [Next Action]

[Continue pattern]

---

## Verification

**You've succeeded when:**
- [ ] [Success criterion]

---

## Troubleshooting

**If [problem]:**
- [Solution]

---

## Next Steps

- [Related task]
- [Advanced variation]
```

## Implementation Steps

1. **Choose template** based on guide type

2. **Fill in metadata:**
   - Time estimate
   - Difficulty level
   - Prerequisites
   - Learning outcomes

3. **Apply Four Facets** to each section:
   - **Data:** Commands, specs, examples
   - **Structure:** Steps, checklists, matrices
   - **Meaning:** Definitions, clarifications
   - **Context:** Why, when, who, where

4. **Add learning progression:**
   - Knowledge level (facts)
   - Skills level (execution)
   - Wisdom level (decisions)

5. **Create anticipatory content:**
   - FAQ with unasked questions
   - Common issues sections
   - Decision matrices

6. **Add role-based paths:**
   - Different user personas
   - Specific next steps per role

7. **Include visual aids:**
   - ASCII diagrams
   - Flow charts
   - Sequence diagrams

8. **Validate completeness:**
   - No dead ends
   - All questions answered
   - Next steps clear
   - Success criteria defined

## Quality Checklist

Before finalizing, verify:

- [ ] Metadata complete (time, difficulty, date)
- [ ] Learning outcomes clear (Knowledge→Skills→Wisdom)
- [ ] Prerequisites with context (why needed, how to verify)
- [ ] Each major section has "Why this matters"
- [ ] Expected results and success criteria provided
- [ ] Common issues addressed (5+ scenarios)
- [ ] FAQ with anticipatory questions (8+ entries)
- [ ] Role-based next steps included
- [ ] Visual diagrams for complex concepts
- [ ] No dead ends (all sections lead somewhere)
- [ ] **Documentation Health Score:** >90/100

## Final Steps

1. **Self-assess:** Run `/doc-health-check` on new guide
2. **Revise:** Address any gaps found
3. **Validate:** Ensure score >90/100
4. **Save:** Write the new guide
5. **Document:** Add to project documentation index

---

**Reference:** `.claude/claude.md` for detailed templates and patterns
