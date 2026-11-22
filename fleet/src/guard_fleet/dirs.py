"""State and config locations, all derived from one home directory."""

from __future__ import annotations

from pathlib import Path


class Dirs:
    def __init__(self, home: Path) -> None:
        self.home = home

    @property
    def config_dir(self) -> Path:
        return self.home / ".config" / "guard-fleet"

    @property
    def consumers_toml(self) -> Path:
        return self.config_dir / "consumers.toml"

    @property
    def self_lock(self) -> Path:
        return self.config_dir / "self.lock"

    @property
    def launcher(self) -> Path:
        return self.home / ".local" / "bin" / "guard-fleet"

    @property
    def state(self) -> Path:
        return self.home / ".local" / "state" / "guard-fleet"

    @property
    def mirror(self) -> Path:
        return self.state / "agent-ratchet.git"

    @property
    def mirror_lock(self) -> Path:
        return self.state / "mirror.lock"

    @property
    def mirror_fetched(self) -> Path:
        return self.state / "mirror.fetched"

    @property
    def run_lock(self) -> Path:
        return self.state / "run.lock"

    def tag_dir(self, tag: str) -> Path:
        return self.state / tag

    def consumer_dir(self, tag: str, short: str) -> Path:
        return self.tag_dir(tag) / short

    def gate_log(self, tag: str, short: str, gate: str) -> Path:
        return self.consumer_dir(tag, short) / f"{gate}.log"

    def ledger(self, tag: str) -> Path:
        return self.tag_dir(tag) / "ledger.jsonl"
