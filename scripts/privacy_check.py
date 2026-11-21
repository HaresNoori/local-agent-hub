"""Scan a repo for denylisted terms in file contents and file names.

Usage: python scripts/privacy_check.py DENYLIST_FILE [ROOT]

DENYLIST_FILE has one case-insensitive term per line (blank lines and lines
starting with '#' are ignored). The denylist is deliberately not stored in
this repository. Exit code 1 if any hit is found.
"""
import sys
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache"}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    terms = [
        t.strip().lower()
        for t in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
        if t.strip() and not t.startswith("#")
    ]
    root = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).resolve().parents[1]
    hits = 0
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if SKIP_DIRS & set(rel.parts):
            continue
        name = str(rel).replace("\\", "/").lower()
        for t in terms:
            if t in name:
                print(f"NAME  {rel}: {t!r}")
                hits += 1
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(lines, 1):
            low = line.lower()
            for t in terms:
                if t in low:
                    print(f"{rel}:{n}: {t!r}")
                    hits += 1
    print(f"{hits} hit(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
