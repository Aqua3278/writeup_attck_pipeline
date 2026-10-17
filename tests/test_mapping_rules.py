"""Soft-validation pattern still available for ValidateService."""

from wap.mapping.rules import WEAK_REASON


def test_weak_reason_pattern_still_available_for_validate():
    assert WEAK_REASON.search("maybe this is valid accounts")
    assert not WEAK_REASON.search("Authentication succeeded with test:test")
