"""Legacy technique hard-gate tests removed after ensemble refactor.

Semantic retained/excluded is decided by multi-model voting (see test_ensemble.py).
Keep a smoke check that soft WEAK_REASON still exists for ValidateService.
"""

from wap.mapping.rules import WEAK_REASON


def test_weak_reason_pattern_still_available_for_validate():
    assert WEAK_REASON.search("This aligns with network discovery")
    assert not WEAK_REASON.search("Authentication succeeded with test:test")
