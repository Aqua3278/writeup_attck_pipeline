from wap.mapping.candidates import generate_candidates

CAT = [
    "T1595",
    "T1190",
    "T1078",
    "T1550",
    "T1550.004",
    "T1110",
    "T1046",
    "T1059",
]


def test_ffuf_candidates_include_t1595():
    c = generate_candidates(
        action="目录枚举",
        evidence="ffuf -w wordlist -u http://t/FUZZ",
        catalog_ids=CAT,
    )
    assert "T1595" in c


def test_plain_curl_no_high_risk_candidates():
    c = generate_candidates(
        action="访问首页",
        evidence="curl http://lab/",
        catalog_ids=CAT,
    )
    assert "T1595" not in c
    assert "T1190" not in c
    assert c == []


def test_cookie_alone_no_t1550_candidate():
    c = generate_candidates(
        action="访问 dashboard",
        evidence="Cookie: session=abc GET /dashboard",
        catalog_ids=CAT,
    )
    assert "T1550" not in c
    assert "T1550.004" not in c


def test_password_alone_no_t1078_candidate():
    c = generate_candidates(
        action="提交密码",
        evidence="password=test",
        catalog_ids=CAT,
    )
    assert "T1078" not in c


def test_comment_creds_yields_t1078_candidate():
    c = generate_candidates(
        action="发现凭据",
        evidence="found in HTML comment test:test",
        catalog_ids=CAT,
    )
    assert "T1078" in c
