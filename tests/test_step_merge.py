from wap.analyze.step_merge import merge_behavioral_steps
from wap.models.schemas import AttackStep, EvidenceType


def _s(seq: int, action: str, evidence: str, step_type: str = "reconnaissance") -> AttackStep:
    return AttackStep(
        step_id=f"s{seq}",
        writeup_id="w",
        sequence=seq,
        action=action,
        evidence=evidence,
        evidence_location="",
        evidence_type=EvidenceType.direct,
        step_type=step_type,
        phase="侦察",
    )


def test_merge_consecutive_http_probes():
    steps = [
        _s(1, "GET /", "curl http://t/"),
        _s(2, "GET /robots.txt", "curl http://t/robots.txt"),
        _s(3, "GET /sitemap.xml", "curl http://t/sitemap.xml"),
        _s(4, "使用 test:test 登录", "POST /login password=test", "credential_access"),
    ]
    out = merge_behavioral_steps(steps)
    assert len(out) == 2
    assert "robots" in out[0].evidence or "合并" in out[0].action or "探测" in out[0].action
    assert out[1].step_type == "credential_access"


def test_do_not_merge_across_exploit():
    steps = [
        _s(1, "探测首页", "GET /"),
        _s(2, "发送 SSTI payload", "POST / {{7*7}}", "exploitation"),
    ]
    out = merge_behavioral_steps(steps)
    assert len(out) == 2
