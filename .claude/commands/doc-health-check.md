---
description: Check documentation health score using Four Facets Framework
---

You are assessing documentation quality using the **Four Facets Framework**.

## Assessment Process

For the specified documentation file, provide a comprehensive health check:

### 1. Four Facets Scoring

Evaluate each facet from 0-25 points:

#### Data (The "What") - /25

**Criteria:**
- [ ] Commands and syntax documented (5 pts)
- [ ] Configuration options listed (5 pts)
- [ ] Version requirements specified (5 pts)
- [ ] Performance benchmarks included (5 pts)
- [ ] Code examples provided (5 pts)

**Score:** __/25
**Missing:** [list gaps]

#### Structure (The "How") - /25

**Criteria:**
- [ ] Clear hierarchy and navigation (5 pts)
- [ ] Numbered steps for procedures (5 pts)
- [ ] Checklists with checkboxes (5 pts)
- [ ] Decision matrices for choices (5 pts)
- [ ] Visual diagrams for complex flows (5 pts)

**Score:** __/25
**Missing:** [list gaps]

#### Meaning (The "Which") - /25

**Criteria:**
- [ ] Technical terms defined (5 pts)
- [ ] Examples show actual usage (5 pts)
- [ ] Comparisons between options (5 pts)
- [ ] Severity/priority explained (5 pts)
- [ ] Ambiguities clarified (5 pts)

**Score:** __/25
**Missing:** [list gaps]

#### Context (The "Why, Where, Who, When") - /25

**Criteria:**
- [ ] Why each step matters (5 pts)
- [ ] When to use specific patterns (5 pts)
- [ ] Who should use which approach (5 pts)
- [ ] Where to get help (5 pts)
- [ ] Trade-offs explained (5 pts)

**Score:** __/25
**Missing:** [list gaps]

### 2. Documentation Health Score

**Total Score:** __/100

**Rating:**
- 90-100: ⭐⭐⭐⭐⭐ Excellent (Ogawa Coffee level)
- 80-89: ⭐⭐⭐⭐ Good (minor enhancements needed)
- 70-79: ⭐⭐⭐ Fair (moderate improvements needed)
- 60-69: ⭐⭐ Poor (significant enhancement required)
- <60: ⭐ Critical (complete transformation needed)

### 3. Learning Progression Assessment

Evaluate coverage of three levels:

**Level 1: Knowledge (Can repeat facts)**
- Present: [Yes/Partial/No]
- Coverage: __%
- Examples: [list what's there]
- Missing: [list gaps]

**Level 2: Skills (Can execute tasks)**
- Present: [Yes/Partial/No]
- Coverage: __%
- Examples: [list what's there]
- Missing: [list gaps]

**Level 3: Wisdom (Can choose wisely)**
- Present: [Yes/Partial/No]
- Coverage: __%
- Examples: [list what's there]
- Missing: [list gaps]

### 4. Ogawa Coffee Principles Check

**Anticipatory Completeness:**
- [ ] FAQ answers unasked questions
- [ ] Common issues addressed proactively
- [ ] Edge cases covered
- **Score:** __/10

**Multi-Modal Learning:**
- [ ] Text explanations
- [ ] Visual diagrams
- [ ] Code examples
- [ ] Tables/matrices
- [ ] Checklists
- **Score:** __/10

**Safety Without Patronizing:**
- [ ] Warnings are contextual
- [ ] Security implications explained
- [ ] Trade-offs presented honestly
- **Score:** __/10

**Nothing Missing:**
- [ ] Every section has next steps
- [ ] No dead ends
- [ ] All questions answered
- [ ] Complete information provided
- **Score:** __/10

**Ogawa Coffee Score:** __/40

### 5. User Journey Coverage

For each persona, assess support:

**Individual Developer:**
- Onboarding: [Excellent|Good|Fair|Poor]
- Task execution: [Excellent|Good|Fair|Poor]
- Decision support: [Excellent|Good|Fair|Poor]
- Coverage: __%

**Team Lead:**
- Onboarding: [Excellent|Good|Fair|Poor]
- Task execution: [Excellent|Good|Fair|Poor]
- Decision support: [Excellent|Good|Fair|Poor]
- Coverage: __%

**Security Team:**
- Onboarding: [Excellent|Good|Fair|Poor]
- Task execution: [Excellent|Good|Fair|Poor]
- Decision support: [Excellent|Good|Fair|Poor]
- Coverage: __%

**OSS Maintainer:**
- Onboarding: [Excellent|Good|Fair|Poor]
- Task execution: [Excellent|Good|Fair|Poor]
- Decision support: [Excellent|Good|Fair|Poor]
- Coverage: __%

### 6. Critical Gaps Analysis

**Priority 1: Must Fix (Blockers)**
1. [Gap with impact on user success]
2. [Another critical gap]

**Priority 2: Should Fix (Major Improvements)**
1. [Significant enhancement opportunity]
2. [Another major gap]

**Priority 3: Nice to Have (Polish)**
1. [Minor improvement]
2. [Enhancement opportunity]

### 7. Recommendations

**Immediate Actions:**
1. [Most critical fix with expected impact]
2. [Second priority]
3. [Third priority]

**Quick Wins (High Impact, Low Effort):**
- [Enhancement that's easy but valuable]
- [Another quick win]

**Strategic Improvements (High Impact, High Effort):**
- [Major enhancement worth the investment]
- [Another strategic improvement]

### 8. Predicted Impact of Enhancements

If all recommendations implemented:

**Before → After:**
- Health Score: __/100 → __/100 (+__ points)
- Time to first success: __ min → __ min (-__%)
- Support tickets: Baseline → -__%
- User satisfaction: __/10 → __/10
- Task completion rate: __% → __%

### 9. Comparison to Standards

**vs. Ogawa Coffee FAQ:**
- Anticipatory design: [Better|Equal|Worse]
- Completeness: [Better|Equal|Worse]
- Multi-modal learning: [Better|Equal|Worse]

**vs. Project Best Practices (QUICK_START.md):**
- Structure: [Better|Equal|Worse]
- Context: [Better|Equal|Worse]
- User journey support: [Better|Equal|Worse]

### 10. Summary Report

```markdown
# Documentation Health Check Summary

**File:** [filename]
**Assessment Date:** [YYYY-MM-DD]
**Assessor:** Claude Code

## Overall Health

**Score:** __/100 ⭐⭐⭐⭐⭐
**Rating:** [Excellent|Good|Fair|Poor|Critical]
**Ogawa Coffee Compliance:** __/40

## Strengths

- [What this doc does well]
- [Another strength]

## Weaknesses

- [Critical gap]
- [Another weakness]

## Top 3 Recommendations

1. **[Recommendation]** - Impact: [High|Medium|Low], Effort: [High|Medium|Low]
2. **[Recommendation]** - Impact: [High|Medium|Low], Effort: [High|Medium|Low]
3. **[Recommendation]** - Impact: [High|Medium|Low], Effort: [High|Medium|Low]

## Next Steps

- [ ] Address Priority 1 gaps (critical)
- [ ] Implement quick wins
- [ ] Plan strategic improvements
- [ ] Re-assess after enhancements

**Target Health Score:** 90+/100
**Estimated Enhancement Time:** __ hours
```

---

## Usage

Run this command with:
```
/doc-health-check [path/to/documentation.md]
```

Then use results to prioritize enhancements with:
```
/enhance-docs [path/to/documentation.md]
```

**Reference:** `.claude/claude.md` for scoring criteria details
