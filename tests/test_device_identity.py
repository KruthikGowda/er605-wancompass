import unittest

from netpulse.devices.identity import display_name


class DeviceIdentityTests(unittest.TestCase):
    def test_placeholder_router_names_get_a_distinguishable_mac_suffix(self):
        for value in (None, "", "--", "---", "Unknown device", "N/A"):
            with self.subTest(value=value):
                self.assertEqual(display_name(value, "AA-BB-CC-DD-EE-02"),
                                 "Unnamed device (DD-EE-02)")
        self.assertEqual(display_name("--", "aa:bb:cc:dd:ee:02"),
                         "Unnamed device (DD-EE-02)")

    def test_real_router_name_is_preserved_and_bounded(self):
        self.assertEqual(display_name("Bedroom speaker", "AA-BB-CC-DD-EE-02"),
                         "Bedroom speaker")
        self.assertEqual(len(display_name("x" * 100, "bad-mac")), 80)

    def test_invalid_mac_still_gets_a_clear_fallback(self):
        self.assertEqual(display_name("--", "not a MAC"), "Unnamed device")


if __name__ == "__main__":
    unittest.main()
