import pytest

from guard_fleet.pins import PIN_PREFIX, PinError, pin_test_hardcodes, rewrite_pin

P, T = "a" * 40, "b" * 40


@pytest.mark.parametrize("line", [
    f"agent-ratchet @ git+https://github.com/dpopek/agent-ratchet@{P}\n",
    f'  "agent-ratchet[php] @ git+https://github.com/dpopek/agent-ratchet@{P}",  # pin\n',
    f"agent-ratchet[magento] @ git+https://github.com/dpopek/agent-ratchet@{P} \r\n",
    f"guard-core[php,magento] @ git+https://github.com/dpopek/guard-core@{P}\n",
])
def test_pin_rewrite_keeps_quote_indent_extras(line):
    text = b"pytest==8\n" + line.encode() + b"ruff\n"
    assert rewrite_pin(text, P, T) == text.replace(P.encode(), T.encode())


@pytest.mark.parametrize("text", [
    b"pytest\n",
    ("agent-ratchet @ git+https://github.com/dpopek/agent-ratchet@" + P + "\n").encode() * 2,
    b"agent-ratchet @ git+https://github.com/dpopek/agent-ratchet@" + b"c" * 40 + b"\n",
])
def test_pin_rewrite_blocks_on_zero_or_two_matches(text):
    with pytest.raises(PinError):
        rewrite_pin(text, P, T)


def test_pin_rewrite_message_counts_lines():
    text = ("agent-ratchet @ git+https://github.com/dpopek/agent-ratchet@" + P + "\n").encode() * 2
    with pytest.raises(PinError, match=r"2 pin lines for aaaaaaaa"):
        rewrite_pin(text, P, T)


def test_pin_rewrite_does_not_match_a_longer_hex_run():
    text = b"agent-ratchet @ git+https://github.com/dpopek/agent-ratchet@" + P.encode() + b"0\n"
    with pytest.raises(PinError):
        rewrite_pin(text, P, T)


@pytest.mark.parametrize("bad", ["abc", "A" * 40, "g" * 40])
def test_pin_rewrite_rejects_a_malformed_sha(bad):
    text = ("agent-ratchet @ git+https://github.com/dpopek/agent-ratchet@" + P + "\n").encode()
    with pytest.raises(PinError):
        rewrite_pin(text, bad, T)
    with pytest.raises(PinError):
        rewrite_pin(text, P, bad)


def test_pin_prefix_is_the_documented_bytes_pattern():
    assert isinstance(PIN_PREFIX, bytes)


def test_pin_test_hardcodes_detects_the_literal_sha():
    assert pin_test_hardcodes(f'PIN = "{P}"\n'.encode(), P)
    assert not pin_test_hardcodes(b"PIN = read_lock()\n", P)
