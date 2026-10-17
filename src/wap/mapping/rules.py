from __future__ import annotations

"""Lightweight helpers for soft validation of mapping reasons.

Semantic support is decided by direct_llm (see direct_llm.py).
These patterns only flag weak/circular justifications for human review.
"""

import re

# Weak or circular justification cues (soft validation only).
WEAK_REASON = re.compile(
    r"可能|大概|或许|似乎|看起来|猜测|"
    r"\b(maybe|perhaps|might|seems?|guess)\b|"
    r"工具名|仅凭.*关键词|keyword.?only|"
    r"后续结果|倒推|inferred.?from.?later",
    re.I,
)
