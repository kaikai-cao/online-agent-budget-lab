"""H3.3: full attack evaluation on the real Agent execution chain.

Layer 1 (real Agent): adversarial tool-return content from a REAL MCP tool is
    fed to REAL DeepSeek (A1).
Layer 2 (deterministic): the harness actively constructs attack requests that
    truly enter each gate (A2-A6). No result is inferred from a log alone;
    MCP Server receipt and SQLite side effects are read from ground truth.

No frozen H1/H2/H3.1/H3.2 module is modified. This package only reuses them.
"""
