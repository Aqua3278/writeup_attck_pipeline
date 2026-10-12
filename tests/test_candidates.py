from wap.mapping.candidates import generate_candidates, infer_execution_context

CAT = [
    "T1595",
    "T1190",
    "T1078",
    "T1550",
    "T1550.004",
    "T1110",
    "T1046",
    "T1059",
    "T1005",
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


def test_ffuf_plus_auth_success_keeps_scan_and_t1078():
    """Scan hit must not suppress credential-use candidates on the same step."""
    c = generate_candidates(
        action="使用 test:test 完成认证并枚举路径",
        evidence=(
            "Authentication succeeded with `test:test`, "
            "ffuf surfaced `/dashboard`, `/orders`, `/javascript/`"
        ),
        catalog_ids=CAT,
    )
    assert "T1595" in c
    assert "T1046" in c
    assert "T1078" in c


def test_auth_succeeded_with_account_yields_t1078():
    c = generate_candidates(
        action="登录",
        evidence="Authentication succeeded with `test:test`",
        catalog_ids=CAT,
    )
    assert "T1078" in c


def test_login_failed_no_t1078_candidate():
    c = generate_candidates(
        action="尝试登录",
        evidence="Authentication failed with `test:test`",
        catalog_ids=CAT,
    )
    assert "T1078" not in c


def test_login_form_discovered_no_t1078_candidate():
    c = generate_candidates(
        action="发现登录页",
        evidence="login form discovered on `/`",
        catalog_ids=CAT,
    )
    assert "T1078" not in c


def test_auth_with_prior_account_context_yields_t1078():
    """Cross-step: prior selected obtain + current Authenticated → T1078 recall."""
    prior = [
        {
            "action": "credential sweep",
            "evidence": "The credential sweep found `user:user`",
            "sequence": 6,
        }
    ]
    c = generate_candidates(
        action="登录后访问 transactions",
        evidence="Authenticated, `/transactions` rendered stored records",
        catalog_ids=CAT,
        prior_selected_steps=prior,
    )
    assert "T1078" in c


def test_auth_without_identity_or_prior_no_t1078():
    c = generate_candidates(
        action="登录",
        evidence="Authenticated",
        catalog_ids=CAT,
        prior_selected_steps=[],
    )
    assert "T1078" not in c


def test_attacker_local_bash_curl_no_t1059():
    ev = "while read oid; do curl -b cookie http://t/order/$oid/receipt; done"
    assert infer_execution_context(ev) == "attacker_local"
    c = generate_candidates(
        action="bash 循环请求订单",
        evidence=ev,
        catalog_ids=CAT,
    )
    assert "T1059" not in c


def test_ssti_os_popen_recalls_exec_and_collect():
    evidence = (
        'GET /remind?date={{ cycler.__init__.__globals__.os.popen('
        '"cat /app/app.py; env; grep -R FLAG{ /app").read() }}'
    )
    c = generate_candidates(
        action="SSTI globals 链通过 os.popen 执行命令",
        evidence=evidence,
        catalog_ids=CAT,
    )
    assert "T1190" in c
    assert "T1059" in c
    assert "T1005" in c
    assert infer_execution_context(evidence) == "web_server"


def test_ssti_oracle_still_t1190_candidate():
    c = generate_candidates(
        action="算术 oracle 确认 SSTI",
        evidence="GET /remind?date={{7*7}} rendered Reminder will be sent on 49",
        catalog_ids=CAT,
    )
    assert "T1190" in c


def test_xss_payload_t1190_candidate():
    c = generate_candidates(
        action="提交 XSS payload",
        evidence='POST solution=<input autofocus onfocus=alert("XSS")>',
        catalog_ids=CAT,
    )
    assert "T1190" in c


def test_cat_readme_t1005_candidate_only():
    """High-recall file signal; retained is Gate's job."""
    c = generate_candidates(
        action="读文件",
        evidence="cat README.md",
        catalog_ids=CAT,
    )
    assert "T1005" in c
