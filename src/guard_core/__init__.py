"""Tombstone: the ``guard_core`` package was removed in agent-ratchet 4.0; import ``agent_ratchet`` instead."""

TOMBSTONE_TEXT = "guard_core was removed in agent-ratchet 4.0; import agent_ratchet instead (see 'agent-ratchet migrate-imports')"

raise ModuleNotFoundError(TOMBSTONE_TEXT, name="guard_core")
