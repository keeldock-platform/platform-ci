import json
import unittest

import perf_shadow as subject


class PerformanceShadowTests(unittest.TestCase):
    def test_harness_emits_complete_feedback_without_a_pass_conclusion(self):
        result = subject.run_harness(250)
        decoded = json.loads(subject.encode_result(result))
        self.assertEqual(decoded["schema_version"], 1)
        self.assertEqual(decoded["mode"], "shadow")
        self.assertEqual(decoded["status"], "feedback-only")
        self.assertEqual(decoded["samples"], 250)
        self.assertTrue(decoded["measurements_complete"])
        self.assertEqual(set(decoded["would_exceed"]), {"elapsed_ms", "extra_bytes"})
        self.assertNotIn("pass", decoded.values())

    def test_harness_bounds_workload_size(self):
        for sample_rows in (0, -1, subject.MAX_SAMPLE_ROWS + 1, True):
            with self.subTest(sample_rows=sample_rows):
                with self.assertRaisesRegex(ValueError, "sample-count-invalid"):
                    subject.run_harness(sample_rows)


if __name__ == "__main__":
    unittest.main()
