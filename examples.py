"""
Examples & Demonstrations
--------------------------
Shows how to use the password_checker module programmatically.
Run with: python examples.py
"""

from password_checker import analyze_password, print_report


def example_basic_usage():
    """Basic: analyze a single password and print report."""
    print("\n" + "="*55)
    print("  EXAMPLE 1 — Basic Usage")
    print("="*55)

    password = "MyP@ssw0rd2024!"
    result = analyze_password(password)
    print_report(result)


def example_batch_analysis():
    """Batch: analyze many passwords and compare scores."""
    print("\n" + "="*55)
    print("  EXAMPLE 2 — Batch Comparison Table")
    print("="*55)

    passwords = [
        ("Too short",     "abc"),
        ("Dictionary",    "password"),
        ("Common combo",  "Password1"),
        ("Better",        "P@ssw0rd!"),
        ("Good",          "Tr0ub4dor&3"),
        ("Strong",        "X#9kL$mQ2!vR@pZ8"),
        ("Very strong",   "k#8Lm!Qr9@pZ2$vN5^wT"),
    ]

    print(f"\n  {'Label':<16} {'Score':>6}  {'Strength':<10}  {'Entropy':>10}  {'Length':>6}")
    print("  " + "-"*55)
    for label, pwd in passwords:
        r = analyze_password(pwd)
        icon = {"Weak": "🔴", "Medium": "🟡", "Strong": "🟢"}[r.strength]
        print(f"  {label:<16} {r.score:>6}  {icon} {r.strength:<8}  {r.entropy_bits:>8.1f}b  {r.length:>6}")
    print()


def example_programmatic_access():
    """Programmatic: access individual analysis fields."""
    print("\n" + "="*55)
    print("  EXAMPLE 3 — Accessing Individual Fields")
    print("="*55)

    result = analyze_password("Secure@Pass99!")

    print(f"\n  password length : {result.length}")
    print(f"  entropy (bits)  : {result.entropy_bits:.2f}")
    print(f"  charset size    : {result.charset_size}")
    print(f"  unique chars    : {result.unique_chars}")
    print(f"  score           : {result.score}")
    print(f"  strength        : {result.strength}")
    print(f"  has_upper       : {result.has_upper}")
    print(f"  has_lower       : {result.has_lower}")
    print(f"  has_digit       : {result.has_digit}")
    print(f"  has_special     : {result.has_special}")
    print(f"  suggestions     : {result.suggestions}")


def example_entropy_education():
    """Educational: show how entropy grows with length and charset."""
    import math
    print("\n" + "="*55)
    print("  EXAMPLE 4 — Entropy Growth Table")
    print("="*55)
    print(f"\n  {'Length':>8}  {'Charset=26':>12}  {'Charset=62':>12}  {'Charset=94':>12}")
    print("  " + "-"*50)
    for length in [6, 8, 10, 12, 16, 20]:
        e26 = length * math.log2(26)
        e62 = length * math.log2(62)
        e94 = length * math.log2(94)
        print(f"  {length:>8}  {e26:>10.1f}b  {e62:>10.1f}b  {e94:>10.1f}b")
    print()


if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║   PASSWORD STRENGTH CHECKER — Examples & Demos  🔐  ║")
    print("╚══════════════════════════════════════════════════════╝")
    example_basic_usage()
    example_batch_analysis()
    example_programmatic_access()
    example_entropy_education()
