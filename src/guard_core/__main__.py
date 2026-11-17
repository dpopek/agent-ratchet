from __future__ import annotations

import sys

from agent_ratchet.cli import main

if __name__ == "__main__":
    print("agent-ratchet: 'python -m guard_core' is deprecated and removed in 4.0; use 'python -m agent_ratchet'", file=sys.stderr)
    sys.exit(main())
