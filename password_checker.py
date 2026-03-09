"""
╔══════════════════════════════════════════════════════════════╗
║           PASSWORD STRENGTH CHECKER 🔐                       ║
║   Analyzes passwords by entropy, variety & length           ║
╚══════════════════════════════════════════════════════════════╝

Author  : Password Strength Checker Tool
Version : 1.0.0
Purpose : Classify passwords as Weak / Medium / Strong
"""

import math
import re
import string
import sys
from dataclasses import dataclass, field
from typing import List, Tuple


# ─────────────────────────────────────────────
#  DATA DEFINITIONS
# ─────────────────────────────────────────────

@dataclass
class PasswordAnalysis:
    """
    Holds all analysis results for a single password.

    Attributes
    ----------
    password        : The raw password string (partially masked for display)
    length          : Total character count
    has_lower       : Contains lowercase letters (a-z)
    has_upper       : Contains uppercase letters (A-Z)
    has_digit       : Contains numeric digits (0-9)
    has_special     : Contains special/punctuation characters
    has_space       : Contains space characters
    unique_chars    : Count of distinct characters used
    charset_size    : Calculated alphabet pool size (used for entropy)
    entropy_bits    : Shannon-like entropy in bits (log2 formula)
    score           : Numeric score  0–100
    strength        : Human-readable label: 'Weak' | 'Medium' | 'Strong'
    suggestions     : List of improvement tips
    """
    password:      str
    length:        int        = 0
    has_lower:     bool       = False
    has_upper:     bool       = False
    has_digit:     bool       = False
    has_special:   bool       = False
    has_space:     bool       = False
    unique_chars:  int        = 0
    charset_size:  int        = 0
    entropy_bits:  float      = 0.0
    score:         int        = 0
    strength:      str        = "Weak"
    suggestions:   List[str]  = field(default_factory=list)


# ─────────────────────────────────────────────
#  CORE ANALYSIS FUNCTIONS
# ─────────────────────────────────────────────

def detect_character_classes(password: str) -> Tuple[bool, bool, bool, bool, bool]:
    """
    Definition / Learning Procedure
    --------------------------------
    Scan every character in the password and detect which
    character CLASSES are present.

    Character Classes:
      • Lowercase  — a … z          (26 symbols)
      • Uppercase  — A … Z          (26 symbols)
      • Digit      — 0 … 9          (10 symbols)
      • Special    — punctuation /  (32 symbols)
      • Space      — ' '            ( 1 symbol )

    Returns
    -------
    (has_lower, has_upper, has_digit, has_special, has_space)
    """
    has_lower   = bool(re.search(r'[a-z]', password))
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_digit   = bool(re.search(r'\d',    password))
    has_special = bool(re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>/?\\|`~]', password))
    has_space   = ' ' in password
    return has_lower, has_upper, has_digit, has_special, has_space


def calculate_charset_size(has_lower: bool, has_upper: bool,
                            has_digit: bool, has_special: bool,
                            has_space: bool) -> int:
    """
    Definition / Learning Procedure
    --------------------------------
    The CHARSET SIZE (pool size) is the number of possible
    symbols the attacker must consider per character position.

    Larger pool → exponentially harder to brute-force.

    Pool contributions:
      lowercase  → +26
      uppercase  → +26
      digits     → +10
      special    → +32
      space      → + 1
    """
    size = 0
    if has_lower:   size += 26
    if has_upper:   size += 26
    if has_digit:   size += 10
    if has_special: size += 32
    if has_space:   size +=  1
    return size


def calculate_entropy(password_length: int, charset_size: int) -> float:
    """
    Definition / Learning Procedure
    --------------------------------
    ENTROPY measures unpredictability in bits.

    Formula:
        H = L × log₂(N)

    Where:
        H  = entropy (bits)
        L  = password length
        N  = charset size (pool size)

    Interpretation:
        < 28 bits  → Very Weak   (cracked in seconds)
        28–35 bits → Weak
        36–59 bits → Medium
        60–127 bits→ Strong
        128+ bits  → Very Strong

    The higher the entropy, the harder the brute-force attack.
    """
    if charset_size == 0 or password_length == 0:
        return 0.0
    return password_length * math.log2(charset_size)


def score_password(analysis: PasswordAnalysis) -> Tuple[int, List[str]]:
    """
    Definition / Learning Procedure
    --------------------------------
    SCORING SYSTEM — assigns points across multiple criteria:

    ┌──────────────────────────────────┬────────┐
    │ Criterion                        │ Points │
    ├──────────────────────────────────┼────────┤
    │ Length ≥  8                      │   10   │
    │ Length ≥ 12                      │   10   │
    │ Length ≥ 16                      │   10   │
    │ Length ≥ 20                      │   10   │
    │ Has lowercase letters            │    5   │
    │ Has uppercase letters            │   10   │
    │ Has digits                       │   10   │
    │ Has special characters           │   15   │
    │ Entropy ≥ 40 bits                │   10   │
    │ Entropy ≥ 60 bits                │   10   │
    │ Unique chars > 50 % of length    │    5   │
    │ No common patterns (penalty)     │  -15   │
    └──────────────────────────────────┴────────┘

    Max raw score: 100 (capped)

    Classification:
        0  – 39  → 🔴 Weak
        40 – 69  → 🟡 Medium
        70 – 100 → 🟢 Strong
    """
    score = 0
    suggestions = []

    # ── Length scoring ──
    if analysis.length >= 8:  score += 10
    else: suggestions.append("Use at least 8 characters.")

    if analysis.length >= 12: score += 10
    else: suggestions.append("Use at least 12 characters for better security.")

    if analysis.length >= 16: score += 10
    else: suggestions.append("16+ characters make passwords significantly harder to crack.")

    if analysis.length >= 20: score += 10

    # ── Character variety ──
    if analysis.has_lower:
        score += 5
    else:
        suggestions.append("Add lowercase letters (a-z).")

    if analysis.has_upper:
        score += 10
    else:
        suggestions.append("Add uppercase letters (A-Z).")

    if analysis.has_digit:
        score += 10
    else:
        suggestions.append("Add numbers (0-9).")

    if analysis.has_special:
        score += 15
    else:
        suggestions.append("Add special characters (!@#$%^&* etc.).")

    # ── Entropy bonuses ──
    if analysis.entropy_bits >= 40:
        score += 10
    if analysis.entropy_bits >= 60:
        score += 10

    # ── Uniqueness bonus ──
    if analysis.length > 0 and (analysis.unique_chars / analysis.length) > 0.5:
        score += 5

    # ── Common pattern penalty ──
    common_patterns = [
        r'(.)\1{2,}',           # repeated chars (aaa, 111)
        r'(012|123|234|345|456|567|678|789)',  # sequential digits
        r'(abc|bcd|cde|def|efg|fgh)',          # sequential letters
        r'(qwerty|asdf|zxcv)',                 # keyboard walks
        r'(password|pass|pwd|admin|login)',    # dictionary words
    ]
    for pattern in common_patterns:
        if re.search(pattern, analysis.password.lower()):
            score -= 15
            suggestions.append("Avoid common patterns, sequences, or dictionary words.")
            break

    # ── Clamp score ──
    score = max(0, min(100, score))
    return score, suggestions


def classify_strength(score: int) -> str:
    """
    Definition / Learning Procedure
    --------------------------------
    Maps numeric score to a STRENGTH LABEL:

        Score  0–39  → Weak   (easily guessable)
        Score 40–69  → Medium (moderate resistance)
        Score 70–100 → Strong (high resistance)
    """
    if score < 40:
        return "Weak"
    elif score < 70:
        return "Medium"
    else:
        return "Strong"


# ─────────────────────────────────────────────
#  MAIN ORCHESTRATOR
# ─────────────────────────────────────────────

def analyze_password(password: str) -> PasswordAnalysis:
    """
    Full Analysis Pipeline
    ----------------------
    Step 1 → Detect character classes
    Step 2 → Calculate charset (pool) size
    Step 3 → Compute entropy in bits
    Step 4 → Score the password
    Step 5 → Classify strength
    Step 6 → Return complete PasswordAnalysis object
    """
    result = PasswordAnalysis(password=password)

    # Step 1 — Character class detection
    (result.has_lower, result.has_upper,
     result.has_digit, result.has_special,
     result.has_space) = detect_character_classes(password)

    # Step 2 — Length & uniqueness
    result.length       = len(password)
    result.unique_chars = len(set(password))

    # Step 3 — Charset size
    result.charset_size = calculate_charset_size(
        result.has_lower, result.has_upper,
        result.has_digit, result.has_special, result.has_space
    )

    # Step 4 — Entropy
    result.entropy_bits = calculate_entropy(result.length, result.charset_size)

    # Step 5 — Score
    result.score, result.suggestions = score_password(result)

    # Step 6 — Classify
    result.strength = classify_strength(result.score)

    return result


# ─────────────────────────────────────────────
#  DISPLAY FUNCTIONS
# ─────────────────────────────────────────────

STRENGTH_ICONS = {"Weak": "🔴", "Medium": "🟡", "Strong": "🟢"}
STRENGTH_BARS  = {
    "Weak":   "██░░░░░░░░",
    "Medium": "█████░░░░░",
    "Strong": "██████████",
}


def mask_password(password: str) -> str:
    """Show first 2 and last 1 chars, mask the rest."""
    if len(password) <= 3:
        return "*" * len(password)
    return password[:2] + "*" * (len(password) - 3) + password[-1]


def print_report(analysis: PasswordAnalysis) -> None:
    """Pretty-print the full analysis report to stdout."""
    icon  = STRENGTH_ICONS[analysis.strength]
    bar   = STRENGTH_BARS[analysis.strength]
    sep   = "─" * 52

    print(f"\n{sep}")
    print(f"  PASSWORD STRENGTH REPORT  🔐")
    print(sep)
    print(f"  Password (masked) : {mask_password(analysis.password)}")
    print(f"  Strength          : {icon}  {analysis.strength}")
    print(f"  Score             : {analysis.score}/100  {bar}")
    print(sep)
    print(f"  📏  Length         : {analysis.length} characters")
    print(f"  🔤  Unique chars   : {analysis.unique_chars}")
    print(f"  🎲  Entropy        : {analysis.entropy_bits:.1f} bits")
    print(f"  🔡  Charset size   : {analysis.charset_size} symbols")
    print(sep)
    print("  Character Classes:")
    print(f"    Lowercase  (a-z)  : {'✅' if analysis.has_lower   else '❌'}")
    print(f"    Uppercase  (A-Z)  : {'✅' if analysis.has_upper   else '❌'}")
    print(f"    Digits     (0-9)  : {'✅' if analysis.has_digit   else '❌'}")
    print(f"    Special (!@#…)    : {'✅' if analysis.has_special else '❌'}")
    if analysis.suggestions:
        print(sep)
        print("  💡  Suggestions:")
        for tip in analysis.suggestions:
            print(f"      • {tip}")
    print(f"{sep}\n")


# ─────────────────────────────────────────────
#  INTERACTIVE CLI
# ─────────────────────────────────────────────

def run_interactive() -> None:
    """
    Interactive mode — prompts user to enter passwords
    until they type 'exit' or press Ctrl-C.
    """
    print("\n╔══════════════════════════════════════════╗")
    print("║   PASSWORD STRENGTH CHECKER  🔐          ║")
    print("║   Type 'exit' to quit                    ║")
    print("╚══════════════════════════════════════════╝")

    while True:
        try:
            pwd = input("\n  Enter password: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n  Goodbye! Stay secure 🔒\n")
            break

        if pwd.lower() == "exit":
            print("\n  Goodbye! Stay secure 🔒\n")
            break

        if not pwd:
            print("  ⚠️  Please enter a non-empty password.")
            continue

        result = analyze_password(pwd)
        print_report(result)


def run_demo() -> None:
    """Run a demo with sample passwords to showcase all strength levels."""
    demo_passwords = [
        "abc",
        "password",
        "Password1",
        "P@ssw0rd!2024",
        "X#9kL$mQ2!vR@pZ8&nT",
    ]
    print("\n╔══════════════════════════════════════════╗")
    print("║   DEMO — Password Strength Checker 🔐    ║")
    print("╚══════════════════════════════════════════╝")
    for pwd in demo_passwords:
        result = analyze_password(pwd)
        print_report(result)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--demo":
            run_demo()
        else:
            # Single password passed as argument
            result = analyze_password(sys.argv[1])
            print_report(result)
    else:
        run_interactive()
