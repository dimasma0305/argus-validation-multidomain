import unittest
from dataclasses import dataclass

from multidomain_scoring import flag_coverage


@dataclass(frozen=True)
class Origin:
    id: str


class FlagCoverageTests(unittest.TestCase):
    def setUp(self):
        self.entries = [Origin("first:root"), Origin("second:root"), Origin("third:root")]
        self.origins = self.entries + [Origin("first:hidden"), Origin("second:hidden"), Origin("third:hidden")]
        self.required = {"first:hidden", "second:hidden", "third:hidden"}

    def test_entry_response_counts_for_its_program(self):
        complete, programs, hidden = flag_coverage(
            {"first:root", "second:root"}, self.origins, self.entries, self.required)
        self.assertFalse(complete)
        self.assertEqual(programs, 0.6667)
        self.assertEqual(hidden, 0.0)

    def test_hidden_or_entry_response_completes_each_program(self):
        self.assertEqual(flag_coverage(
            {"first:root", "second:hidden", "third:root"},
            self.origins, self.entries, self.required), (True, 1.0, 0.3333))

    def test_unknown_origin_does_not_count(self):
        complete, programs, _ = flag_coverage(
            {"first:root", "second:root", "third:unknown"},
            self.origins, self.entries, self.required)
        self.assertFalse(complete)
        self.assertEqual(programs, 0.6667)

    def test_single_program_keeps_origin_rule(self):
        self.assertEqual(flag_coverage(
            {"first:root"}, self.origins[:1] + self.origins[3:4],
            self.entries[:1], {"first:hidden"}), (False, 1.0, 0.0))


if __name__ == "__main__":
    unittest.main()
