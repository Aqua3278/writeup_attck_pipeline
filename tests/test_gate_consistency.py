"""Post-ensemble: Stage-1 recall alignment (no demote_retained gates)."""

from __future__ import annotations

from wap.mapping.candidates import generate_candidates
from wap.mapping.evidence_signals import AUTH_SUCCESS_RE, infer_execution_context

CAT = ["T1078", "T1059", "T1190", "T1110", "T1005", "T1595"]


def test_auth_success_signal_for_candidate_recall():
    text = "Authenticated, `/transactions` rendered stored records"
    assert AUTH_SUCCESS_RE.search(text)


def test_ssti_os_popen_still_recalled_as_t1059():
    evidence = (
        'GET /remind?date={{ cycler.__init__.__globals__.os.popen('
        '"cat /app/app.py").read() }}'
    )
    c = generate_candidates(
        action="SSTI os.popen RCE",
        evidence=evidence,
        catalog_ids=CAT,
    )
    assert "T1059" in c
    assert infer_execution_context(evidence) == "web_server"


def test_idor_purpose_can_recall_t1190():
    """General recall: purpose/evidence mentioning IDOR should surface T1190."""
    c = generate_candidates(
        action="批量读取订单收据",
        evidence="curl order receipt loop found FLAG in other user's order",
        purpose="Confirm IDOR on /order/{id}/receipt",
        catalog_ids=CAT,
    )
    assert "T1190" in c
