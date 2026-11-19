"""R2.4 phase-1: independent event witness & trustworthy metering (prototype).

Scope boundary (MUST be preserved in every report):
  - An independent event source can reveal "an observed execution request has
    no matching metering record", event deletion, duplication and status
    inconsistency.
  - It CANNOT know what the service did internally beyond observed events, and
    CANNOT by itself establish the TRUE resource consumption of a request.
  - Detecting under-reporting is NOT the same as proving a metering value real.

No ZKP / Halo2 / TEE / Merkle tree / real LLM / real MCP here.
"""
