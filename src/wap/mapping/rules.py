from __future__ import annotations

"""Lightweight helpers retained after ensemble refactor.

Technique-specific demote_retained hard gates were removed. Semantic
support/reject is decided by multi-model voting (see ensemble.py).

WEAK_REASON remains for ValidateService soft warnings on mapping_reason text.
"""

import re

# Soft validation only — does NOT change mapping_status in the map pipeline.
WEAK_REASON = re.compile(
    r"("
    r"aligns with|related to|typically used|usually used|"
    r"may (be|indicate)|could be|possibly|semantic|"
    r"语义相关|通常用于|可能属于|看起来像|与.+相关|"
    r"因为.*阶段|最终获得|result of the chain|"
    r"step_type\s*=|因为\s*step_type|由于\s*step_type|"
    r"因为.?候选|candidate\s*(implies|suggests)"
    r")",
    re.I,
)
