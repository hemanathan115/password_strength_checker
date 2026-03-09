"""
Unit Tests for Password Strength Checker
-----------------------------------------
Tests all core functions individually and the full analysis pipeline.
Run with: python test_password_checker.py
"""

import unittest
import math
from password_checker import (
    detect_character_classes,
    calculate_charset_size,
    calculate_entropy,
    score_password,
    classify_strength,
    analyze_password,
    PasswordAnalysis,
)


class TestCharacterClassDetection(unittest.TestCase):
    """Tests for detect_character_classes()"""

    def test_all_lowercase(self):
        lower, upper, digit, special, space = detect_character_classes("abcdef")
        self.assertTrue(lower)
        self.assertFalse(upper)
        self.assertFalse(digit)
        self.assertFalse(special)
        self.assertFalse(space)

    def test_all_classes_present(self):
        lower, upper, digit, special, space = detect_character_classes("aA1! x")
        self.assertTrue(lower)
        self.assertTrue(upper)
        self.assertTrue(digit)
        self.assertTrue(special)
        self.assertTrue(space)

    def test_digits_only(self):
        lower, upper, digit, special, space = detect_character_classes("123456")
        self.assertFalse(lower)
        self.assertFalse(upper)
        self.assertTrue(digit)
        self.assertFalse(special)

    def test_special_chars(self):
        _, _, _, special, _ = detect_character_classes("!@#$%^")
        self.assertTrue(special)

    def test_empty_string(self):
        lower, upper, digit, special, space = detect_character_classes("")
        self.assertFalse(any([lower, upper, digit, special, space]))


class TestCharsetSize(unittest.TestCase):
    """Tests for calculate_charset_size()"""

    def test_lowercase_only(self):
        size = calculate_charset_size(True, False, False, False, False)
        self.assertEqual(size, 26)

    def test_upper_and_lower(self):
        size = calculate_charset_size(True, True, False, False, False)
        self.assertEqual(size, 52)

    def test_alphanumeric(self):
        size = calculate_charset_size(True, True, True, False, False)
        self.assertEqual(size, 62)

    def test_full_charset(self):
        size = calculate_charset_size(True, True, True, True, False)
        self.assertEqual(size, 94)

    def test_with_space(self):
        size = calculate_charset_size(True, True, True, True, True)
        self.assertEqual(size, 95)

    def test_nothing(self):
        size = calculate_charset_size(False, False, False, False, False)
        self.assertEqual(size, 0)


class TestEntropyCalculation(unittest.TestCase):
    """Tests for calculate_entropy()"""

    def test_zero_length(self):
        self.assertEqual(calculate_entropy(0, 62), 0.0)

    def test_zero_charset(self):
        self.assertEqual(calculate_entropy(10, 0), 0.0)

    def test_known_value(self):
        # 8 chars, charset=62 → 8 * log2(62) ≈ 47.63
        result = calculate_entropy(8, 62)
        self.assertAlmostEqual(result, 8 * math.log2(62), places=4)

    def test_entropy_increases_with_length(self):
        e1 = calculate_entropy(8, 62)
        e2 = calculate_entropy(16, 62)
        self.assertGreater(e2, e1)

    def test_entropy_increases_with_charset(self):
        e1 = calculate_entropy(10, 26)
        e2 = calculate_entropy(10, 94)
        self.assertGreater(e2, e1)


class TestScoring(unittest.TestCase):
    """Tests for score_password()"""

    def _make_analysis(self, password):
        return analyze_password(password)

    def test_very_short_weak(self):
        result = self._make_analysis("ab")
        self.assertLess(result.score, 40)
        self.assertEqual(result.strength, "Weak")

    def test_common_password_penalized(self):
        result = self._make_analysis("password123")
        # Should lose points for common pattern
        self.assertLess(result.score, 70)

    def test_strong_password_high_score(self):
        result = self._make_analysis("X#9kL$mQ2!vR@pZ8&nT")
        self.assertGreaterEqual(result.score, 70)
        self.assertEqual(result.strength, "Strong")

    def test_medium_password(self):
        result = self._make_analysis("Password1!")
        self.assertGreaterEqual(result.score, 40)

    def test_score_clamped_to_100(self):
        result = self._make_analysis("X#9kL$mQ2!vR@pZ8&nTqW3@")
        self.assertLessEqual(result.score, 100)
        self.assertGreaterEqual(result.score, 0)


class TestClassification(unittest.TestCase):
    """Tests for classify_strength()"""

    def test_weak_range(self):
        for score in [0, 10, 20, 39]:
            self.assertEqual(classify_strength(score), "Weak")

    def test_medium_range(self):
        for score in [40, 50, 60, 69]:
            self.assertEqual(classify_strength(score), "Medium")

    def test_strong_range(self):
        for score in [70, 80, 90, 100]:
            self.assertEqual(classify_strength(score), "Strong")

    def test_boundaries(self):
        self.assertEqual(classify_strength(39), "Weak")
        self.assertEqual(classify_strength(40), "Medium")
        self.assertEqual(classify_strength(69), "Medium")
        self.assertEqual(classify_strength(70), "Strong")


class TestFullPipeline(unittest.TestCase):
    """End-to-end tests for analyze_password()"""

    def test_returns_analysis_object(self):
        result = analyze_password("TestPass1!")
        self.assertIsInstance(result, PasswordAnalysis)

    def test_length_correct(self):
        result = analyze_password("Hello")
        self.assertEqual(result.length, 5)

    def test_unique_chars_correct(self):
        result = analyze_password("aabbcc")
        self.assertEqual(result.unique_chars, 3)

    def test_suggestions_populated_for_weak(self):
        result = analyze_password("abc")
        self.assertGreater(len(result.suggestions), 0)

    def test_entropy_nonzero(self):
        result = analyze_password("Hello123!")
        self.assertGreater(result.entropy_bits, 0)

    def test_empty_password(self):
        result = analyze_password("")
        self.assertEqual(result.length, 0)
        self.assertEqual(result.entropy_bits, 0.0)
        self.assertEqual(result.strength, "Weak")


# ─────────────────────────────────────────────
#  RUN ALL TESTS
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🔐 Running Password Strength Checker Unit Tests...\n")
    loader  = unittest.TestLoader()
    suite   = loader.loadTestsFromModule(__import__(__name__))
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    total   = result.testsRun
    passed  = total - len(result.failures) - len(result.errors)
    print(f"\n{'='*50}")
    print(f"  Tests run: {total}  |  Passed: {passed}  |  Failed: {len(result.failures) + len(result.errors)}")
    print(f"{'='*50}\n")
