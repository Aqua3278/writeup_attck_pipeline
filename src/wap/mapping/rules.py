from __future__ import annotations

"""Generic evidence gates for ATT&CK retained (no benchmark-specific branches)."""

import re

from wap.models.schemas import MappingStatus

WEAK_REASON = re.compile(
    r"("
    r"aligns with|related to|typically used|usually used|"
    r"may (be|indicate)|could be|possibly|semantic|"
    r"语义相关|通常用于|可能属于|看起来像|与.+相关|"
    r"因为.*阶段|最终获得|result of the chain|"
    r"step_type\s*=|因为\s*step_type|由于\s*step_type|"
    r"因为.?候选|candidate\s*(implies|suggests)|"
    r"主动发包|主动.?HTTP.?请求|发送.?HTTP.?请求.?本身|"
    r"cookie\s*(存在|携带)|携带.?cookie|"
    r"成功登录.?就|HTTP\s*200.?就|返回.?200.?就"
    r")",
    re.I,
)

# Systematic scanning signals — must appear in HARD evidence (not LLM reason)
SCAN_HARD = re.compile(
    r"("
    r"\b(nmap|masscan|zmap|rustscan)\b|"
    r"\b(ffuf|gobuster|dirb|dirbuster|feroxbuster|wfuzz|dirsearch)\b|"
    r"\b(nikto|nuclei|wpscan)\b|"
    r"\b(wordlist|seclists)\b|\bFUZZ\b|"
    r"port\s*scan|service\s*scan|directory\s*(scan|brut|enum)|"
    r"vuln(?:erability)?\s*scan|"
    r"\bnxc\s+smb\b|\bcrackmapexec\b|"
    r"auxiliary/scanner/|"
    r"批量\s*(探测|扫描|枚举)|字典\s*(扫描|枚举)|目录枚举|端口扫描"
    r")",
    re.I,
)
LIGHT_PROBE = re.compile(r"\b(httpx|whatweb)\b", re.I)
MULTI_TARGET = re.compile(
    r"("
    r"\b\d{1,3}(?:\.\d{1,3}){3}\s*-\s*\d+\b|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b|"
    r"-l\s+\S+|hosts?\.txt|urls?\.txt|target(s)?\.txt|"
    r"多个目标|批量.?url|batch\s+of|against\s+multiple"
    r")",
    re.I,
)

STRONG_ALT_AUTH = re.compile(
    r"("
    r"\b(steal|stolen|hijack|replay)\b|"
    r"another\s+user|other\s+user|victim.?s?\s+session|"
    r"session\s+fixation|"
    r"forged?\s+(jwt|token|cookie|session)|"
    r"crafted?\s+(jwt|token)|"
    r"窃取|劫持|重放|"
    r"他人.?session|他人.?cookie|非本人.?会话|"
    r"伪造.?(jwt|token|cookie|会话)|篡改.?(jwt|token)"
    r")",
    re.I,
)

ACCOUNT_OBTAIN = re.compile(
    r"("
    r"password\s*spray|bruteforc|credential\s*stuff|"
    r"default\s*(cred|password|account)|hardcoded|"
    r"found\s+(in\s+)?(comment|source|page)|"
    r"discover(?:ed)?\s+(cred|password|user|account)|"
    r"dump(?:ed)?|crack(?:ed)?|as-?rep|kerberoast|ntlm\s*hash|"
    r"from\s+comment|in\s+html\s+comment|"
    r"喷洒|爆破|默认口令|注释中发现|硬编码|窃取.?凭据|破解|dump|"
    r"获取.?凭据|发现.?密码|发现.?账户|发现.?凭据"
    r")",
    re.I,
)
# Explicit auth success only — not login page/form, Set-Cookie, HTTP 302/200, welcome.
AUTH_SUCCESS = re.compile(
    r"("
    r"authentication\s+succeed(?:ed)?|"
    r"authentication\s+successful|"
    r"successfully\s+authenticated|"
    r"authenticated\s+successfully|"
    r"login\s+succeed(?:ed)?|"
    r"login\s+successful|"
    r"successfully\s+logged\s*in|"
    r"logged\s*in\s+successfully|"
    r"log\s*in\s+success|"
    r"登录成功|成功登录|认证成功"
    r")",
    re.I,
)
# Concrete account / credential identity present in the step (not obtain/discovery).
ACCOUNT_IDENTITY = re.compile(
    r"("
    r"[`'\"]?[A-Za-z0-9._-]{1,64}:[A-Za-z0-9._\-!@#$%]{1,64}[`'\"]?|"
    r"\buser(name)?\s*[:=]\s*[`'\"]?[A-Za-z0-9._@-]{1,64}|"
    r"\b(logged\s*in|authenticated)\s+as\s+[`'\"]?[A-Za-z0-9._@-]{1,64}|"
    r"\bas\s+[`'\"]?[A-Za-z0-9._@-]{2,64}\b|"
    r"以\s*\S+\s*身份|"
    r"(用户名|账号|账户)\s*[:=]?\s*\S+"
    r")",
    re.I,
)
AUTH_FAIL = re.compile(
    r"("
    r"authentication\s+fail|"
    r"login\s+fail|"
    r"failed\s+(to\s+)?(authenticate|log\s*in)|"
    r"invalid\s+cred|"
    r"wrong\s+password|"
    r"incorrect\s+password|"
    r"登录失败|认证失败|密码错误|凭据无效|口令错误"
    r")",
    re.I,
)
PROBE_ONLY = re.compile(
    r"("
    r"vulnerable|not vulnerable|check(?:ing)?\s+(for\s+)?vuln|"
    r"探测|检测漏洞|是否存在|is vulnerable|probe|fingerprint"
    r")",
    re.I,
)
HTTP_STATUS_ONLY = re.compile(
    r"("
    r"HTTP\s*[/]?1\.[01]\s*(200|302|301|404|403)|"
    r"status\s*[:=]?\s*(200|302|404)|"
    r"\b(200|302|404)\s*OK\b|"
    r"返回\s*(200|302|404)|响应.?(200|302|404)"
    r")",
    re.I,
)
PAYLOAD_SENT = re.compile(
    r"("
    r"\bssti\b|payload|\{\{|<%|inject|"
    r"发送.?payload|注入.?payload|尝试.?利用"
    r")",
    re.I,
)
EXPLOIT_EFFECT = re.compile(
    r"("
    r"\brce\b|webshell|command\s+prompt|got\s+(a\s+)?shell|"
    r"remote\s+code|code\s+execution|"
    r"other\s+user|another\s+user|unauthorized|"
    r"access\s+control\s+bypass|idor\s+(confirm|success|proven)|"
    r"order\s+belong(?:s|ing)\s+to|flag\s+of\s+another|"
    r"成功利用|远程代码执行|获得.?shell|非预期|"
    r"其他用户|他人.?订单|越权|绕过.?访问控制|"
    r"命令执行结果|模板被执行"
    r")",
    re.I,
)

LOCAL_ENCODE = re.compile(r"\b(base64|encode|decode|xor|rot13)\b", re.I)
EVADE_HINT = re.compile(
    r"(bypass|evade|obfuscat|defender|av\b|edr|检测|绕过|混淆|规避)",
    re.I,
)
C2_HINT = re.compile(
    r"(c2|command.?and.?control|beacon|callback|exfil|通信|信道)",
    re.I,
)
VICTIM_TRANSFER = re.compile(
    r"("
    r"upload\s+to|written\s+to|dropped\s+(on|to)|"
    r"on\s+the\s+(target|victim|host)|"
    r"上传.?到|写入.?目标|落盘|目标主机"
    r")",
    re.I,
)
LATERAL = re.compile(
    r"("
    r"from\s+.+\s+to\s+|lateral|pivot|"
    r"横向|跳板|从.+到.+(主机|机器|服务器)"
    r")",
    re.I,
)


def _prefix(tid: str | None, p: str) -> bool:
    return bool(tid and tid.startswith(p))


def _hard(action: str, evidence: str, supporting: str) -> str:
    return f"{action}\n{evidence}\n{supporting}"


def _true_scan(hard: str) -> bool:
    if SCAN_HARD.search(hard):
        return True
    if LIGHT_PROBE.search(hard) and MULTI_TARGET.search(hard):
        return True
    return False


def demote_retained(
    *,
    technique_id: str | None,
    status: MappingStatus,
    reason: str,
    evidence: str,
    supporting: str,
    step_type: str,
    action: str,
) -> tuple[MappingStatus, str]:
    """
    Hard precision gates. Uses HARD evidence (action/evidence/supporting),
    NOT the LLM reason text — models must not talk past gates.
    """
    if status != MappingStatus.retained:
        return status, reason

    hard = _hard(action, evidence, supporting)
    soft_reason = reason or ""

    if WEAK_REASON.search(soft_reason):
        return (
            MappingStatus.excluded,
            reason + "；[自动降级] 理由含推测/关键词等价/候选确认偏置，不足以 retained。",
        )
    if not (evidence or "").strip():
        return (
            MappingStatus.excluded,
            reason + "；[自动降级] retained 缺少 evidence。",
        )
    if len((supporting or "").strip()) < 4 and len(soft_reason.strip()) < 12:
        return (
            MappingStatus.excluded,
            reason + "；[自动降级] 未给出可核对的行为依据。",
        )

    # --- T1595 ---
    if _prefix(technique_id, "T1595"):
        if not _true_scan(hard):
            return (
                MappingStatus.excluded,
                reason
                + "；[自动降级] 单次/业务请求 ≠ Active Scanning；"
                "hard evidence 须含系统化扫描/枚举（工具+字典/批量/多目标等）。",
            )

    # --- T1550 ---
    if _prefix(technique_id, "T1550"):
        if not STRONG_ALT_AUTH.search(hard):
            return (
                MappingStatus.excluded,
                reason
                + "；[自动降级] cookie/session 存在或自用 ≠ T1550；"
                "须有窃取/重放/伪造/他人会话等 hard evidence。",
            )

    # --- T1078 Valid Accounts ---
    # Retain: ACCOUNT_IDENTITY + AUTH_SUCCESS + no AUTH_FAIL.
    # Credential discovery/acquisition need NOT appear on the same step.
    if _prefix(technique_id, "T1078"):
        if AUTH_FAIL.search(hard):
            return (
                MappingStatus.excluded,
                reason
                + "；[自动降级] authentication/login failed 或无效凭据 ≠ 成功认证，"
                "不能 retained T1078。",
            )
        if not ACCOUNT_IDENTITY.search(hard):
            return (
                MappingStatus.excluded,
                reason
                + "；[自动降级] 无明确账户/用户身份（如 user:pass、username=、as alice），"
                "不能 retained T1078。",
            )
        if not AUTH_SUCCESS.search(hard):
            return (
                MappingStatus.excluded,
                reason
                + "；[自动降级] 无明确认证成功表述（authentication succeeded / 登录成功等）；"
                "login page/form、Set-Cookie、HTTP 302/200、welcome 单独不足。",
            )

    # --- T1190 ---
    if _prefix(technique_id, "T1190"):
        if EXPLOIT_EFFECT.search(hard):
            pass
        elif HTTP_STATUS_ONLY.search(hard) and not EXPLOIT_EFFECT.search(hard):
            return (
                MappingStatus.excluded,
                reason + "；[自动降级] HTTP 状态码/可达性不足以 retained T1190。",
            )
        elif PROBE_ONLY.search(hard) and not EXPLOIT_EFFECT.search(hard):
            return (
                MappingStatus.excluded,
                reason + "；[自动降级] 漏洞探测/指纹 ≠ 公开应用利用。",
            )
        elif PAYLOAD_SENT.search(hard) and not EXPLOIT_EFFECT.search(hard):
            return (
                MappingStatus.excluded,
                reason + "；[自动降级] 仅发送 payload 而无非预期效果，不能 retained T1190。",
            )
        else:
            return (
                MappingStatus.excluded,
                reason + "；[自动降级] 缺少利用成功/越权/RCE 等效果 hard evidence。",
            )

    # --- T1059: need interpreter + attack-context execution, not every CLI ---
    if _prefix(technique_id, "T1059"):
        if not re.search(
            r"\b(powershell|pwsh|cmd\.exe|bash|sh\b|python\s+-c|Invoke-Expression)\b|"
            r"命令执行|命令提示符",
            hard,
            re.I,
        ):
            return (
                MappingStatus.excluded,
                reason + "；[自动降级] 缺少命令/脚本解释器执行的 hard evidence。",
            )

    # --- T1105 ---
    if _prefix(technique_id, "T1105"):
        if re.search(r"\b(curl|wget)\b", hard, re.I) and not VICTIM_TRANSFER.search(hard):
            # curl to attacker's own machine / local download ≠ ingress to victim
            if not re.search(r"\.(sh|exe|elf|ps1|dll)\b", hard, re.I):
                return (
                    MappingStatus.excluded,
                    reason + "；[自动降级] 普通 curl/wget ≠ Ingress Tool Transfer。",
                )

    # --- T1005 ---
    if _prefix(technique_id, "T1005"):
        if not re.search(
            r"(/etc/passwd|ntds|sam\b|敏感|机密|credentials?\s+file|收集)",
            hard,
            re.I,
        ):
            return (
                MappingStatus.excluded,
                reason + "；[自动降级] 普通读文件/页面 ≠ Data from Local System。",
            )

    # --- T1021 ---
    if _prefix(technique_id, "T1021"):
        if re.search(r"\b(ssh|rdp|winrm)\b", hard, re.I) and not LATERAL.search(hard):
            # mention of protocol alone is weak; allow if clear remote auth to host
            if not re.search(
                r"\b(psexec|wmiexec|evil-winrm|enter-pssession)\b|"
                r"ssh\s+\w+@|登录.?远程|remote\s+shell",
                hard,
                re.I,
            ):
                return (
                    MappingStatus.excluded,
                    reason + "；[自动降级] 仅出现 SSH/RDP 字样 ≠ Remote Services 横向移动。",
                )

    if technique_id in ("T1132", "T1132.001", "T1132.002"):
        if LOCAL_ENCODE.search(hard) and not C2_HINT.search(hard):
            return (
                MappingStatus.excluded,
                reason + "；[自动降级] 本地编解码不足以构成 T1132。",
            )
    if _prefix(technique_id, "T1027"):
        if LOCAL_ENCODE.search(hard) and not EVADE_HINT.search(hard):
            return (
                MappingStatus.excluded,
                reason + "；[自动降级] 缺少防御规避目的的混淆 hard evidence。",
            )

    if _prefix(technique_id, "T1588"):
        if step_type == "tool_setup" or re.search(
            r"\b(git\s+clone|pip\s+install|go\s+build|venv)\b", hard, re.I
        ):
            return (
                MappingStatus.excluded,
                reason + "；[自动降级] 下载/编译工具默认不计入覆盖。",
            )

    return status, reason


def one_line(text: str, max_len: int = 120) -> str:
    s = re.sub(r"\s+", " ", (text or "").strip())
    if len(s) <= max_len:
        return s
    return s[: max_len - 1].rstrip() + "…"
