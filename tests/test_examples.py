"""The examples are documentation that must keep working."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def load(name):
    sys.path.insert(0, str(EXAMPLES))
    try:
        spec = importlib.util.spec_from_file_location("example_" + name, EXAMPLES / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(EXAMPLES))


class ExampleTests(unittest.TestCase):
    def run_example(self, name):
        with contextlib.redirect_stdout(io.StringIO()):
            return load(name).main()

    def test_submit_approve_complete_reaches_completed_through_every_step(self):
        result = self.run_example("submit_approve_complete")
        self.assertEqual(result["final_state"], "completed")
        for event in ("dispatched", "approved", "claimed", "completed"):
            self.assertIn(event, result["events"])

    def test_refused_unapproved_shows_every_refusal(self):
        result = self.run_example("refused_unapproved")
        self.assertIsNone(result["claim"])
        self.assertEqual((result["wrong_digest"], result["worker_approve"], result["anonymous"]), (409, 403, 401))
        self.assertEqual((result["still"], result["after_stop"]), ("awaiting_approval", "cancelled"))


if __name__ == "__main__":
    unittest.main()
