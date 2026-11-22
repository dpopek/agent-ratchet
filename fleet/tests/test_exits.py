import pytest

from guard_fleet.exits import FleetExit, UsageError, Cancelled, combine

OK, BLOCKED, USAGE, SHA_MISMATCH, CANCELLED, NO_HELPER, FAILED = (
    FleetExit.OK, FleetExit.BLOCKED, FleetExit.USAGE, FleetExit.SHA_MISMATCH,
    FleetExit.CANCELLED, FleetExit.NO_HELPER, FleetExit.FAILED)


def test_values():
    assert [int(e) for e in FleetExit] == [0, 1, 2, 3, 4, 5, 6]


def test_combine_precedence():
    assert combine([OK, NO_HELPER, BLOCKED]) is BLOCKED
    assert combine([BLOCKED, CANCELLED]) is CANCELLED
    assert combine([CANCELLED, FAILED, OK]) is FAILED
    assert combine([NO_HELPER, OK]) is NO_HELPER
    assert combine([]) is OK
    with pytest.raises(ValueError):
        combine([USAGE])
    with pytest.raises(ValueError):
        combine([OK, SHA_MISMATCH])


def test_exceptions_are_exceptions():
    assert issubclass(UsageError, Exception) and issubclass(Cancelled, Exception)
    assert str(UsageError("bad target")) == "bad target"
