# D9.3.1 package

This package contains a deterministic patch script and the stage documentation.

1. Extract the ZIP into the repository root (`D:\Research\online-agent-budget-lab`), preserving `.git`.
2. Run `python scripts/apply_d93_1_hardening.py` from the repository root.
3. Run the complete suite with `PYTHONWARNINGS=error::ResourceWarning` as documented in `docs/D9.3.1_SINGLE_NODE_HARDENING.md`.
4. Inspect `git diff --check`, `git diff --stat`, and `git status --short`.

The script preflights all expected source anchors before writing and stores original files in a temporary backup directory. It does not commit or push.
