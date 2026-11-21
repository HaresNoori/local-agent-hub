"""Static checks that the documented Python requirement matches the package metadata.

These checks read files and parse source; they do not run the code under another interpreter.
A syntax parse at the feature level of 3.11 catches newer grammar but not newer library calls, so
this is evidence of source compatibility, not a substitute for running the suite on 3.11.
"""
from __future__ import annotations

import ast
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PythonRequirementTests(unittest.TestCase):
    def test_readme_states_the_same_minimum_as_pyproject(self):
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        match = re.fullmatch(r">=\s*(\d+\.\d+)", metadata["project"]["requires-python"])
        self.assertIsNotNone(match, "requires-python should be a simple lower bound")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Python %s or later" % match.group(1), readme)

    def test_every_source_file_parses_with_the_python_3_11_grammar(self):
        files = [p for folder in ("hub", "scripts", "examples", "tests") for p in (ROOT / folder).glob("*.py")]
        self.assertGreater(len(files), 20)
        for path in files:
            with self.subTest(file=path.name):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 11))


if __name__ == "__main__":
    unittest.main()
