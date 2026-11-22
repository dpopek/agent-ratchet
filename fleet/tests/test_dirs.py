from pathlib import Path

from guard_fleet.dirs import Dirs


def test_layout(tmp_path):
    d = Dirs(tmp_path)
    s = tmp_path / ".local/state/guard-fleet"
    assert d.config_dir == tmp_path / ".config/guard-fleet"
    assert d.consumers_toml == d.config_dir / "consumers.toml"
    assert d.self_lock == d.config_dir / "self.lock"
    assert d.launcher == tmp_path / ".local/bin/guard-fleet"
    assert d.state == s
    assert (d.mirror, d.mirror_lock, d.mirror_fetched, d.run_lock) == (
        s / "agent-ratchet.git", s / "mirror.lock", s / "mirror.fetched", s / "run.lock")
    assert d.tag_dir("v4.4.0") == s / "v4.4.0"
    assert d.consumer_dir("v4.4.0", "alpha") == s / "v4.4.0/alpha"
    assert d.gate_log("v4.4.0", "alpha", "g1") == s / "v4.4.0/alpha/g1.log"
    assert d.ledger("v4.4.0") == s / "v4.4.0/ledger.jsonl"
    assert isinstance(d.state, Path)
