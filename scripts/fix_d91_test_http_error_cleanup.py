from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "test_online_coordinator.py"
OLD = '''        with self.assertRaises(HTTPError) as ctx:\n            urlopen(req, timeout=3)\n        self.assertEqual(ctx.exception.code, 401)\n        self.assertEqual(self.coordinator.inspect()["global_used_count"], 0)\n'''
NEW = '''        with self.assertRaises(HTTPError) as ctx:\n            urlopen(req, timeout=3)\n        error = ctx.exception\n        try:\n            self.assertEqual(error.code, 401)\n        finally:\n            error.close()\n        self.assertEqual(self.coordinator.inspect()["global_used_count"], 0)\n'''


def main() -> int:
    if not TARGET.is_file():
        raise SystemExit(f"Expected D9.1 test file was not found: {TARGET}")

    source = TARGET.read_text(encoding="utf-8")
    if NEW in source:
        print("D9.1 HTTPError cleanup is already applied; no changes made.")
        return 0

    count = source.count(OLD)
    if count != 1:
        raise SystemExit(
            "Expected exactly one unpatched HTTPError test block, "
            f"found {count}; refusing to modify an unexpected file."
        )

    TARGET.write_text(source.replace(OLD, NEW, 1), encoding="utf-8", newline="")
    print("Patched tests/test_online_coordinator.py: the captured HTTPError is now closed explicitly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
