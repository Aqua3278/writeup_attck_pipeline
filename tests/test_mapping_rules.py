from wap.mapping.rules import demote_retained
from wap.models.schemas import MappingStatus


def test_weak_reason_demoted():
    st, _ = demote_retained(
        technique_id="T1046",
        status=MappingStatus.retained,
        reason="This aligns with network discovery",
        evidence="nmap -sV 10.0.0.1",
        supporting="nmap scan",
        step_type="reconnaissance",
        action="scan",
    )
    assert st == MappingStatus.excluded


def test_single_curl_not_t1595():
    st, _ = demote_retained(
        technique_id="T1595",
        status=MappingStatus.retained,
        reason="系统性主动扫描满足定义",  # reason must NOT bypass hard gate
        evidence="execute_curl args: -s -i http://lab-30cc2125/",
        supporting="GET /",
        step_type="reconnaissance",
        action="对目标 Web 根路径发起 HTTP 请求",
    )
    assert st == MappingStatus.excluded


def test_ffuf_is_t1595():
    st, _ = demote_retained(
        technique_id="T1595",
        status=MappingStatus.retained,
        reason="批量目录枚举满足主动扫描定义",
        evidence="ffuf -w SecLists/Discovery/Web-Content/common.txt -u http://t/FUZZ",
        supporting="使用 ffuf 配合字典批量枚举路径",
        step_type="reconnaissance",
        action="目录枚举",
    )
    assert st == MappingStatus.retained


def test_httpx_single_not_t1595():
    st, _ = demote_retained(
        technique_id="T1595",
        status=MappingStatus.retained,
        reason="httpx 指纹",
        evidence="httpx -u http://lab-bc87dd88/",
        supporting="单目标 httpx",
        step_type="reconnaissance",
        action="HTTP 指纹",
    )
    assert st == MappingStatus.excluded


def test_own_cookie_not_t1550():
    st, _ = demote_retained(
        technique_id="T1550",
        status=MappingStatus.retained,
        reason="请求携带 Cookie",
        evidence="Cookie: session=abc123 GET /dashboard",
        supporting="使用登录后的 session 访问",
        step_type="collection",
        action="访问 dashboard",
    )
    assert st == MappingStatus.excluded


def test_stolen_session_t1550_ok():
    st, _ = demote_retained(
        technique_id="T1550.004",
        status=MappingStatus.retained,
        reason="重放窃取的他人 session",
        evidence="replay stolen session cookie of another user",
        supporting="重放他人 session",
        step_type="credential_access",
        action="会话重放",
    )
    assert st == MappingStatus.retained


def test_plain_login_not_t1078():
    st, _ = demote_retained(
        technique_id="T1078",
        status=MappingStatus.retained,
        reason="成功登录",
        evidence="POST /login user=demo pass=demo → logged in",
        supporting="登录成功",
        step_type="credential_access",
        action="登录",
    )
    assert st == MappingStatus.excluded


def test_discover_without_auth_not_t1078():
    st, _ = demote_retained(
        technique_id="T1078",
        status=MappingStatus.retained,
        reason="发现凭据",
        evidence="found in HTML comment test:test",
        supporting="注释中发现 test:test",
        step_type="credential_access",
        action="发现凭据",
    )
    assert st == MappingStatus.excluded


def test_comment_creds_login_t1078_ok():
    st, _ = demote_retained(
        technique_id="T1078",
        status=MappingStatus.retained,
        reason="使用注释凭据登录成功",
        evidence="found in HTML comment test:test then login → logged in 302 FOUND Location: /dashboard",
        supporting="注释中发现 test:test 并登录成功",
        step_type="credential_access",
        action="用发现的凭据登录",
    )
    assert st == MappingStatus.retained


def test_http_200_not_t1190():
    st, _ = demote_retained(
        technique_id="T1190",
        status=MappingStatus.retained,
        reason="请求返回 200",
        evidence="GET /order/999999/receipt → HTTP/1.1 200",
        supporting="接口返回 200",
        step_type="exploitation",
        action="访问订单接口",
    )
    assert st == MappingStatus.excluded


def test_ssti_payload_only_not_t1190():
    st, _ = demote_retained(
        technique_id="T1190",
        status=MappingStatus.retained,
        reason="发送 SSTI payload",
        evidence="POST name={{7*7}}",
        supporting="发送 SSTI payload",
        step_type="exploitation",
        action="注入模板",
    )
    assert st == MappingStatus.excluded


def test_t1190_with_effect_ok():
    st, _ = demote_retained(
        technique_id="T1190",
        status=MappingStatus.retained,
        reason="利用成功获得 shell",
        evidence="got a shell after ProxyShell exploit",
        supporting="成功利用获得 shell",
        step_type="exploitation",
        action="利用漏洞",
    )
    assert st == MappingStatus.retained


def test_step_type_reason_demoted():
    st, _ = demote_retained(
        technique_id="T1005",
        status=MappingStatus.retained,
        reason="因为 step_type=collection 所以对应本地收集",
        evidence="cat /etc/passwd",
        supporting="读取文件",
        step_type="collection",
        action="读文件",
    )
    assert st == MappingStatus.excluded


def test_candidate_bias_reason_demoted():
    st, _ = demote_retained(
        technique_id="T1595",
        status=MappingStatus.retained,
        reason="因为候选是 T1595 所以判定为主动扫描",
        evidence="ffuf -w wordlist -u http://t/FUZZ",
        supporting="ffuf 枚举",
        step_type="reconnaissance",
        action="枚举",
    )
    assert st == MappingStatus.excluded
