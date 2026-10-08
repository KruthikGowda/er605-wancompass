import unittest

from netpulse.freshness import age_seconds


class FreshnessAge(unittest.TestCase):
    def test_only_finite_nonnegative_ages_are_known(self):
        self.assertEqual(age_seconds(90, 100), 10)
        self.assertEqual(age_seconds(100, 100), 0)
        for timestamp in (None, True, "bad", float("nan"), float("inf"), 101):
            with self.subTest(timestamp=timestamp):
                self.assertIsNone(age_seconds(timestamp, 100))


if __name__ == "__main__":
    unittest.main()
