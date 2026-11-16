from __future__ import annotations

import ast
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "tests" / "test_online_coordinator.py"

replacements = [
    (
        "        return OnlineBudgetClient(\n"
        "            base_url=self.base_url, gateway_id=gateway_id,\n"
        "            gateway_private_key=key,\n"
        "            coordinator_public_key=self.coordinator_private.public_key(),\n"
        "            coordinator_id=self.COORDINATOR_ID,\n"
        "        )",
        "        return OnlineBudgetClient(\n"
        "            base_url=self.base_url, gateway_id=gateway_id,\n"
        "            gateway_private_key=key,\n"
        "            coordinator_public_key=self.coordinator_private.public_key(),\n"
        "            coordinator_id=self.COORDINATOR_ID,\n"
        "            global_budget_id=self.BUDGET_ID,\n"
        "        )",
    ),
    (
        "        client = OnlineBudgetClient(\n"
        "            base_url=\"http://127.0.0.1:1\", gateway_id=\"gateway-A\",\n"
        "            gateway_private_key=self.gateway_a_private,\n"
        "            coordinator_public_key=self.coordinator_private.public_key(),\n"
        "            coordinator_id=self.COORDINATOR_ID, timeout_seconds=0.2,\n"
        "        )",
        "        client = OnlineBudgetClient(\n"
        "            base_url=\"http://127.0.0.1:1\", gateway_id=\"gateway-A\",\n"
        "            gateway_private_key=self.gateway_a_private,\n"
        "            coordinator_public_key=self.coordinator_private.public_key(),\n"
        "            coordinator_id=self.COORDINATOR_ID,\n"
        "            global_budget_id=self.BUDGET_ID, timeout_seconds=0.2,\n"
        "        )",
    ),
]

if not TARGET.is_file():
    raise SystemExit(f"Required file not found: {TARGET}")

original = TARGET.read_text(encoding="utf-8")
updated = original
changed = 0
for old, new in replacements:
    if new in updated:
        continue
    count = updated.count(old)
    if count != 1:
        raise SystemExit(
            "Patch preflight failed without writing files: "
            f"expected one occurrence, found {count} for block beginning {old.splitlines()[0]!r}"
        )
    updated = updated.replace(old, new, 1)
    changed += 1

# Validate every OnlineBudgetClient construction in tests/examples has an explicit epoch pin.
failures: list[str] = []
scan_roots = [ROOT / "tests", ROOT / "examples"]
for scan_root in scan_roots:
    for path in sorted(scan_root.rglob("*.py")):
        try:
            tree = ast.parse((updated if path == TARGET else path.read_text(encoding="utf-8")), filename=str(path))
        except SyntaxError as exc:
            raise SystemExit(f"Syntax error in {path}: {exc}") from exc
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else None)
            if name == "OnlineBudgetClient" and not any(k.arg == "global_budget_id" for k in node.keywords):
                failures.append(f"{path.relative_to(ROOT)}:{node.lineno}")

if failures:
    raise SystemExit(
        "Patch preflight found OnlineBudgetClient callsites without global_budget_id:\n"
        + "\n".join(failures)
    )

if changed:
    backup_root = Path(tempfile.mkdtemp(prefix="d93_1_client_callers_backup_"))
    backup = backup_root / "tests" / "test_online_coordinator.py"
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(TARGET, backup)
    TARGET.write_text(updated, encoding="utf-8", newline="")
    print(f"Patched {changed} OnlineBudgetClient callsite(s) in tests/test_online_coordinator.py")
    print(f"Backup: {backup}")
else:
    print("All targeted OnlineBudgetClient callsites were already patched.")

print("Verified: all OnlineBudgetClient constructors in tests/ and examples/ pin global_budget_id.")
