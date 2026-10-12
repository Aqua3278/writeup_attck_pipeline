from __future__ import annotations

"""Merge request-level HTTP fragments into behavioral step units (generic)."""

import re
from collections import Counter

from wap.models.schemas import AttackStep

_HTTP_LINE = re.compile(
    r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+/\S*|"
    r"\b(curl|wget|execute_curl)\b|"
    r"https?://\S+",
    re.I,
)
_INTENT_SHIFT = re.compile(
    r"("
    r"\b(login|log\s*in|passwd|password|auth|cookie|session|upload|"
    r"exploit|payload|ssti|sqlmap|shell|rce|ssh|smb|kerberos|hash)\b|"
    r"登录|密码|认证|上传|利用|注入|横向|提权"
    r")",
    re.I,
)
_STATIC_PATH = re.compile(
    r"/(robots\.txt|sitemap\.xml|favicon\.ico|javascript/?|static/|"
    r"assets/|css/|js/|img/)?$",
    re.I,
)


def _is_httpish(step: AttackStep) -> bool:
    blob = f"{step.action}\n{step.evidence}"
    return bool(_HTTP_LINE.search(blob))


def _intent_key(step: AttackStep) -> str:
    """Coarse intent bucket for merge decisions."""
    blob = f"{step.action}\n{step.evidence}".lower()
    if _INTENT_SHIFT.search(blob):
        # keep distinct intents unmerged across different keywords
        m = _INTENT_SHIFT.search(blob)
        return f"shift:{(m.group(0) if m else 'x').lower()}"
    if step.step_type in (
        "tool_setup",
        "data_processing",
        "validation",
        "observation",
        "reconnaissance",
        "discovery",
    ):
        return f"type:{step.step_type}"
    if _is_httpish(step):
        return "http_probe"
    return f"uniq:{step.action[:40]}"


def merge_behavioral_steps(steps: list[AttackStep], max_evidence_chars: int = 1200) -> list[AttackStep]:
    """
    Merge consecutive steps that share the same coarse intent and look like
    request-level Web probing (/, robots, sitemap, …).
    Never merge across clear intent shifts (login/exploit/cred/…).
    """
    if len(steps) < 2:
        return steps

    ordered = sorted(steps, key=lambda s: s.sequence)
    groups: list[list[AttackStep]] = []
    cur: list[AttackStep] = [ordered[0]]

    for s in ordered[1:]:
        prev = cur[-1]
        same = _intent_key(s) == _intent_key(prev)
        both_http = _is_httpish(s) and _is_httpish(prev)
        soft_types = {
            "observation",
            "reconnaissance",
            "discovery",
            "other",
            "validation",
        }
        types_ok = (s.step_type in soft_types) and (prev.step_type in soft_types)
        if same and both_http and types_ok and _intent_key(s).startswith(
            ("http_probe", "type:observation", "type:reconnaissance", "type:discovery")
        ):
            cur.append(s)
        else:
            groups.append(cur)
            cur = [s]
    groups.append(cur)

    merged: list[AttackStep] = []
    for g in groups:
        if len(g) == 1:
            merged.append(g[0])
            continue
        # Build one behavioral unit
        head = g[0]
        evidences = []
        for x in g:
            e = (x.evidence or "").strip()
            if e and e not in evidences:
                evidences.append(e)
        evidence = "\n".join(evidences)
        if len(evidence) > max_evidence_chars:
            evidence = evidence[: max_evidence_chars - 1] + "…"

        type_counts = Counter(x.step_type for x in g)
        step_type = type_counts.most_common(1)[0][0]
        if step_type == "other":
            step_type = "reconnaissance"

        actions = [x.action.strip() for x in g if x.action.strip()]
        # Prefer a unit description over listing GET lines
        if all(_HTTP_LINE.search(a or "") or len(a) < 40 for a in actions):
            action = "对 Web 应用进行路径/资源探测（合并连续同类 HTTP 请求）"
        else:
            action = actions[0]

        merged.append(
            AttackStep(
                step_id=head.step_id,
                writeup_id=head.writeup_id,
                sequence=head.sequence,
                action=action,
                target=head.target,
                input=head.input,
                output=head.output,
                purpose=head.purpose or "合并连续同类探测请求为行为单元",
                prerequisite=head.prerequisite,
                evidence=evidence,
                evidence_location=head.evidence_location,
                evidence_type=head.evidence_type,
                inference=any(x.inference for x in g),
                chunk_id=head.chunk_id,
                step_type=step_type,
                phase=head.phase or "侦察",
            )
        )

    for i, s in enumerate(merged, 1):
        s.sequence = i
    return merged
