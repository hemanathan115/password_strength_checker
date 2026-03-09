# 🔐 Password Strength Checker

> A Python tool that analyzes how strong a password is by checking **length**, **character variety**, **entropy**, and **common patterns** — classifying it as **Weak**, **Medium**, or **Strong**.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Full Program Flow](#full-program-flow)
4. [Definition & Learning Procedure (All Terms)](#definition--learning-procedure-all-terms)
5. [Output Examples](#output-examples)
6. [Installation & Usage](#installation--usage)
7. [File Structure](#file-structure)
8. [Scoring Rubric](#scoring-rubric)
9. [Strength Classification](#strength-classification)
10. [Security Notes](#security-notes)

---

## Overview

The **Password Strength Checker** is a standalone Python tool (no third-party libraries required) that evaluates the security quality of any password. It uses a multi-factor scoring model combining:

- Character variety (lowercase, uppercase, digits, special characters)
- Password length
- Entropy calculation (information-theoretic unpredictability)
- Common pattern detection (keyboard walks, dictionary words, repeats)

---

## Features

| Feature | Description |
|---|---|
| 🔤 Character class detection | Checks for lowercase, uppercase, digits, special chars |
| 📏 Length analysis | Penalizes short passwords, rewards long ones |
| 🎲 Entropy calculation | Uses `H = L × log₂(N)` formula |
| 🔍 Pattern detection | Flags `password`, `qwerty`, `123`, repeated chars, etc. |
| 💡 Improvement tips | Suggests how to make the password stronger |
| 🖥️ Interactive CLI | Prompts user to enter multiple passwords |
| 🎬 Demo mode | Shows examples of Weak / Medium / Strong passwords |
| 📦 No dependencies | Uses only Python standard library |

---

## Full Program Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                  PROGRAM FLOW DIAGRAM                           │
└─────────────────────────────────────────────────────────────────┘

User Input (password string)
         │
         ▼
┌─────────────────────────┐
│  Step 1: Character      │   detect_character_classes(password)
│  Class Detection        │   ─────────────────────────────────
│                         │   Scan each character with regex:
│  has_lower  → a-z       │     re.search(r'[a-z]', password)
│  has_upper  → A-Z       │     re.search(r'[A-Z]', password)
│  has_digit  → 0-9       │     re.search(r'\d',    password)
│  has_special→ !@#…      │     re.search(r'[!@#…]',password)
│  has_space  → ' '       │     ' ' in password
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Step 2: Length &       │   len(password)
│  Uniqueness             │   len(set(password))
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Step 3: Charset        │   calculate_charset_size(...)
│  (Pool) Size            │   ─────────────────────────────────
│                         │   Sum of active character pools:
│  lowercase  → +26       │     if has_lower   → size += 26
│  uppercase  → +26       │     if has_upper   → size += 26
│  digits     → +10       │     if has_digit   → size += 10
│  special    → +32       │     if has_special → size += 32
│  space      → + 1       │     if has_space   → size +=  1
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Step 4: Entropy        │   calculate_entropy(length, charset)
│  Calculation            │   ─────────────────────────────────
│                         │   H = length × log₂(charset_size)
│  H < 28  → Very Weak    │
│  H 28–35 → Weak         │
│  H 36–59 → Medium       │
│  H 60–127→ Strong       │
│  H 128+  → Very Strong  │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Step 5: Scoring        │   score_password(analysis)
│                         │   ─────────────────────────────────
│  Length bonuses  0–40   │   Add points per criterion (table)
│  Variety bonuses 0–40   │   Deduct 15 for common patterns
│  Entropy bonuses 0–20   │   Clamp result to [0, 100]
│  Uniqueness bonus 0–5   │
│  Pattern penalty -15    │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Step 6: Classify       │   classify_strength(score)
│                         │   ─────────────────────────────────
│  Score  0–39  → Weak    │
│  Score 40–69  → Medium  │
│  Score 70–100 → Strong  │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Step 7: Report Output  │   print_report(analysis)
│                         │   ─────────────────────────────────
│  • Masked password      │   Shows masked password, strength
│  • Strength label       │   label, score bar, all metrics,
│  • Score bar            │   and improvement suggestions
│  • Metrics table        │
│  • Suggestions list     │
└─────────────────────────┘
```

---

## Definition & Learning Procedure (All Terms)

### 🔤 Character Classes

A **character class** is a named group of symbols used to describe what kinds of characters are present in a password.

| Class | Symbols | Pool Size | Purpose |
|---|---|---|---|
| Lowercase | a-z | 26 | Basic readability |
| Uppercase | A-Z | 26 | Increases unpredictability |
| Digits | 0-9 | 10 | Adds numeric variety |
| Special | `!@#$%^&*()…` | 32 | Highest entropy contribution |
| Space | ` ` | 1 | Rarely used, adds surprise |

**Learning Procedure:**
```
For each character c in password:
    IF c matches [a-z]     → mark has_lower   = True
    IF c matches [A-Z]     → mark has_upper   = True
    IF c matches [0-9]     → mark has_digit   = True
    IF c matches [!@#$...] → mark has_special = True
    IF c == ' '            → mark has_space   = True
```

---

### 📏 Password Length

**Definition:** The total number of characters in the password.

**Why it matters:** Every extra character multiplies the search space by the charset size. A 12-char password has `N^12` possible values vs `N^8` for an 8-char one.

**Length thresholds used:**
```
length ≥  8 → +10 points  (minimum acceptable)
length ≥ 12 → +10 points  (recommended minimum)
length ≥ 16 → +10 points  (good)
length ≥ 20 → +10 points  (excellent)
```

---

### 🔢 Charset Size (Pool Size)

**Definition:** The number of distinct symbols an attacker must try per character position.

**Formula:**
```
charset_size = 0
if has_lower:   charset_size += 26   # a-z
if has_upper:   charset_size += 26   # A-Z
if has_digit:   charset_size += 10   # 0-9
if has_special: charset_size += 32   # !@#$...
if has_space:   charset_size +=  1   # ' '
```

**Examples:**
| Password Type | Charset Size |
|---|---|
| All lowercase | 26 |
| Lower + upper | 52 |
| Lower + upper + digits | 62 |
| All classes | 95 |

---

### 🎲 Entropy (Bits)

**Definition:** A measure of unpredictability or randomness in a password, expressed in bits.

**Formula:**
```
H = L × log₂(N)

Where:
  H = entropy in bits
  L = password length
  N = charset size (pool size)
```

**Interpretation:**
```
H < 28 bits   → Very Weak   (cracked in milliseconds)
28–35 bits    → Weak        (cracked in minutes–hours)
36–59 bits    → Medium      (cracked in days–months)
60–127 bits   → Strong      (cracked in years–centuries)
128+ bits     → Very Strong (computationally infeasible)
```

**Example calculation:**
```
Password: "Hello123!" → length=9, charset=62+32=94
H = 9 × log₂(94) = 9 × 6.55 = 58.96 bits → Medium
```

---

### 📊 Scoring System

**Definition:** A weighted point system (0–100) that combines all factors into a single quality score.

**Scoring Table:**

| Criterion | Points |
|---|---|
| Length ≥ 8 characters | +10 |
| Length ≥ 12 characters | +10 |
| Length ≥ 16 characters | +10 |
| Length ≥ 20 characters | +10 |
| Has lowercase letters | +5 |
| Has uppercase letters | +10 |
| Has digits | +10 |
| Has special characters | +15 |
| Entropy ≥ 40 bits | +10 |
| Entropy ≥ 60 bits | +10 |
| Unique chars > 50% of length | +5 |
| Common pattern detected | -15 |

**Maximum score: 100** (result is clamped to [0, 100])

---

### 🔍 Common Pattern Detection

**Definition:** Regular-expression rules that identify predictable structures attackers always try first.

**Patterns checked:**
```
(.)\1{2,}          → Repeated characters  (e.g., "aaa", "111")
(123|234|…|789)    → Sequential digits    (e.g., "12345")
(abc|bcd|…|efg)    → Sequential letters   (e.g., "abcde")
(qwerty|asdf|zxcv) → Keyboard walks       (e.g., "qwerty")
(password|admin…)  → Dictionary words     (e.g., "password1")
```

If any pattern is found → **-15 points** and a suggestion is added.

---

### 🏷️ Strength Classification

**Definition:** A human-readable label derived from the numeric score.

```
Score  0 – 39  → 🔴 Weak    (high risk, replace immediately)
Score 40 – 69  → 🟡 Medium  (acceptable, could be improved)
Score 70 – 100 → 🟢 Strong  (good resistance to attacks)
```

---

### 🔑 Unique Character Ratio

**Definition:** The proportion of distinct characters relative to total length.

**Formula:**
```
unique_ratio = len(set(password)) / len(password)
```

A ratio > 0.5 means more than half the characters are different from each other → **+5 bonus points**. Low uniqueness suggests repeating patterns.

---

## Output Examples

### 🔴 Weak Password: `"abc"`
```
────────────────────────────────────────────────────
  PASSWORD STRENGTH REPORT  🔐
────────────────────────────────────────────────────
  Password (masked) : ab*
  Strength          : 🔴  Weak
  Score             : 5/100  ██░░░░░░░░
────────────────────────────────────────────────────
  📏  Length         : 3 characters
  🎲  Entropy        : 14.1 bits
  🔡  Charset size   : 26 symbols
────────────────────────────────────────────────────
  💡  Suggestions:
      • Use at least 8 characters.
      • Add uppercase letters (A-Z).
      • Add numbers (0-9).
      • Add special characters (!@#$%^&* etc.).
```

### 🟡 Medium Password: `"Password1"`
```
  Strength : 🟡  Medium
  Score    : 45/100
  Entropy  : 51.8 bits
```

### 🟢 Strong Password: `"X#9kL$mQ2!vR@pZ8&nT"`
```
  Strength : 🟢  Strong
  Score    : 100/100
  Entropy  : 119.8 bits
```
## Output
<img src="https://github.com/hemanathan115/hemanathan115/blob/main/Picsart_25-12-12_20-00-06-218.jpg" alt="My Photo">



---

## Installation & Usage

### Requirements
- Python 3.7+
- No external libraries needed

### Run Interactive Mode
```bash
python password_checker.py
```

### Check a Single Password (CLI)
```bash
python password_checker.py "MyP@ssw0rd!"
```

### Run Demo Mode
```bash
python password_checker.py --demo
```

### Run Unit Tests
```bash
python test_password_checker.py
```

---

## File Structure

```
password_strength_checker/
├── password_checker.py       # Main tool (all logic + CLI)
├── test_password_checker.py  # Unit tests for all functions
├── examples.py               # Usage examples & demonstrations
└── README.md                 # This file
```

---

## Scoring Rubric

```
┌─────────────────────────────────────────────────────┐
│                 SCORING RUBRIC                      │
├─────────────────────┬───────────┬───────────────────┤
│ Category            │ Max Pts   │ Criteria          │
├─────────────────────┼───────────┼───────────────────┤
│ Length              │    40     │ 4 tiers (8/12/16/20)│
│ Character Variety   │    40     │ lower/upper/dig/spec│
│ Entropy Bonus       │    20     │ 40+ and 60+ bits  │
│ Uniqueness Bonus    │     5     │ >50% unique chars │
│ Pattern Penalty     │   -15     │ common patterns   │
├─────────────────────┼───────────┼───────────────────┤
│ TOTAL (max)         │   100     │                   │
└─────────────────────┴───────────┴───────────────────┘
```

---

## Strength Classification

| Strength | Score Range | Entropy Range | Risk Level |
|---|---|---|---|
| 🔴 Weak | 0–39 | < 36 bits | High — change immediately |
| 🟡 Medium | 40–69 | 36–59 bits | Moderate — improve if possible |
| 🟢 Strong | 70–100 | 60+ bits | Low — suitable for sensitive accounts |

---

## Security Notes

> ⚠️ This tool does **not** store, log, or transmit any passwords.
> All analysis happens locally in memory.

- Entropy formula assumes **random** character placement. Human-chosen passwords with recognizable words have *lower* real-world entropy than calculated.
- Use a **password manager** to generate and store truly random strong passwords.
- Enable **2FA/MFA** in addition to strong passwords for best security.

---

*Built with Python 3 — no external dependencies required.*
