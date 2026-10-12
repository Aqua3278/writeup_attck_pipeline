from __future__ import annotations

"""Stage-1 candidate generation: high recall, never decides retained.

Behavior-signal layers + optional prior *selected* attack-chain context.
Precision gates live in rules.py / verify.py — not here.
"""

import re
from typing import Any, Iterable, Mapping, Optional, Sequence

# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------

_SCAN = re.compile(
    r"("
    r"\b(nmap|masscan|zmap|rustscan|ffuf|gobuster|dirb|dirbuster|"
    r"feroxbuster|wfuzz|dirsearch|nikto|nuclei|wpscan)\b|"
    r"\b(wordlist|seclists)\b|\bFUZZ\b|"
    r"端口扫描|目录枚举|字典\s*(扫描|枚举)|批量\s*(探测|扫描|枚举)|"
    r"auxiliary/scanner/"
    r")",
    re.I,
)
_LIGHT_PROBE = re.compile(r"\b(httpx|whatweb)\b", re.I)
_MULTI = re.compile(
    r"("
    r"\b\d{1,3}(?:\.\d{1,3}){3}\s*-\s*\d+\b|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b|"
    r"-l\s+\S+|hosts?\.txt|urls?\.txt|target(s)?\.txt|"
    r"多个目标|批量.?url"
    r")",
    re.I,
)

_ALT_AUTH = re.compile(
    r"("
    r"\b(steal|stolen|hijack|replay|forged?|crafted?)\b|"
    r"another\s+user|other\s+user|session\s+fixation|"
    r"窃取|劫持|重放|伪造|他人.?session|他人.?cookie"
    r")",
    re.I,
)
_CRED_OBTAIN = re.compile(
    r"("
    r"password\s*spray|bruteforc|credential\s*stuff|credential\s*sweep|"
    r"default\s*(cred|password|account)|hardcoded|"
    r"found\s+(in\s+)?(comment|source|page)|"
    r"discover(?:ed)?\s+(cred|password|user|account)|"
    r"leaks?\s+[`'\"]?[A-Za-z0-9._-]+:|"
    r"from\s+comment|in\s+html\s+comment|html\s+comment|"
    r"喷洒|爆破|默认口令|注释中发现|硬编码|发现.?密码|发现.?凭据|发现.?账户|"
    r"凭据扫描|口令喷洒"
    r")",
    re.I,
)
_SPRAY = re.compile(r"\b(spray|bruteforc|喷洒|爆破|credential\s*sweep)\b", re.I)

# Auth success (candidate recall; gate may be stricter)
_AUTH_OK = re.compile(
    r"("
    r"authentication\s+succeed(?:ed)?|"
    r"authentication\s+successful|"
    r"successfully\s+authenticated|"
    r"authenticated\s+successfully|"
    r"\bauthenticated\b|"
    r"login\s+succeed(?:ed)?|"
    r"login\s+successful|"
    r"successfully\s+logged\s*in|"
    r"logged\s*in\s+successfully|"
    r"log\s*in\s+success|"
    r"登录成功|成功登录|认证成功"
    r")",
    re.I,
)
_AUTH_FAIL_OR_SURFACE = re.compile(
    r"("
    r"authentication\s+fail|"
    r"login\s+fail|"
    r"failed\s+(to\s+)?(authenticate|log\s*in)|"
    r"login\s+(form|page)\b|"
    r"discovered\s+login|"
    r"登录失败|认证失败|登录表单|登录页"
    r")",
    re.I,
)
# Concrete account / credential identity (user:pass, username=, as alice, …)
_ACCOUNT_ID = re.compile(
    r"("
    r"[`'\"]?[A-Za-z0-9._-]{1,64}:[A-Za-z0-9._\-!@#$%]{1,64}[`'\"]?|"
    r"\buser(name)?\s*[:=]\s*[`'\"]?[A-Za-z0-9._@-]{1,64}|"
    r"\b(logged\s*in|authenticated)\s+as\s+[`'\"]?[A-Za-z0-9._@-]{1,64}|"
    r"\bwith\s+[`'\"]?[A-Za-z0-9._-]+:[^\s`'\"`,;]+|"
    r"\b(as|using)\s+[`'\"]?[A-Za-z0-9._-]{2,64}\b|"
    r"以\s*\S+\s*身份|"
    r"(用户名|账号|账户)\s*[:=]?\s*\S+|"
    r"使用\s*[`'\"]?[A-Za-z0-9._-]+:[A-Za-z0-9._\-!@#$%]+"
    r")",
    re.I,
)

_EXPLOIT = re.compile(
    r"("
    r"(?:^|[^A-Za-z])(exploit|ssti|rce|webshell|proxyshell|idor|payload)(?:[^A-Za-z]|$)|"
    r"\{\{[^{}]{0,200}\}\}|"
    r"__globals__|__builtins__|"
    r"jinja2|模板注入|利用|注入"
    r")",
    re.I,
)

# Command / script execution *signals* (not sufficient for retained)
_CMD_EXEC = re.compile(
    r"("
    r"\b(bash|sh|zsh|pwsh|powershell|cmd\.exe)\b|"
    r"python\s+-c\b|"
    r"\bos\.system\b|\bos\.popen\b|\bsubprocess\b|"
    r"\bexec\s*\(|\bsystem\s*\(|"
    r"command\s+execution|execute\s+command|"
    r"命令执行|执行命令"
    r")",
    re.I,
)

# File / data access signals
_FILE_ACCESS = re.compile(
    r"("
    r"\b(cat|grep|find)\b|"
    r"\btype\s+[A-Za-z]:\\|"
    r"read\s+file|open\s*/?\s*read|"
    r"/etc/passwd|"
    r"/app/[A-Za-z0-9_./\-]+\.py\b|"
    r"\benv\b|environment\s+var|"
    r"sensitive\s+file|application\s+source|"
    r"\bcredentials?\b|"
    r"\bdump(?:ed)?\b|"
    r"读取文件|读取敏感|环境变量|敏感文件|收集数据"
    r")",
    re.I,
)

_REMOTE = re.compile(r"\b(ssh|rdp|winrm|psexec|wmiexec|evil-winrm)\b", re.I)
_INGRESS = re.compile(
    r"\b(wget|curl).{0,80}\.(sh|exe|elf|ps1)\b|\b(upload|上传|ingress)\b",
    re.I,
)
_OBFUSC = re.compile(r"\b(obfuscat|混淆|绕过.?检测|defender)\b", re.I)
_C2 = re.compile(r"\b(c2|beacon|callback|exfil)\b", re.I)
_TOOL_GET = re.compile(r"\b(git\s+clone|pip\s+install)\b", re.I)
_ACCOUNT_DISC = re.compile(r"\b(userenum|账户发现)\b", re.I)

# Execution context helpers (candidate recall only)
_CTX_ATTACKER_LOCAL = re.compile(
    r"("
    r"while\s+read\b|"
    r"\bkali_shell\b|"
    r"for\s+\w+\s+in\s+\$\(|"
    r"\bbash\b.{0,120}\b(curl|wget|httpie)\b|"
    r"\b(curl|wget)\b.{0,80}\b(for|while|loop)\b|"
    r"本地脚本|本机自动化|attacker[-_ ]?(host|side|local)|"
    r"automation\s+(script|loop)"
    r")",
    re.I,
)
_CTX_WEB_SERVER = re.compile(
    r"("
    r"\b(ssti|jinja2?|twig|freemarker)\b|"
    r"\{\{[^{}]{0,200}\}\}|"
    r"__globals__|__builtins__|"
    r"\bos\.popen\b|\bos\.system\b|"
    r"模板注入|服务端|web\s*server|in[- ]?app\s+exec"
    r")",
    re.I,
)
_CTX_TARGET_HOST = re.compile(
    r"("
    r"\b(psexec|wmiexec|evil-winrm)\b|"
    r"ssh\s+\S+@|"
    r"on\s+the\s+(target|victim|remote)\s+host|"
    r"目标主机|受害主机|远程主机上"
    r")",
    re.I,
)

# Back-compat names used by older audits / imports
_SCAN_STRONG = _SCAN
_CRED_ABUSE = _CRED_OBTAIN
_AUTH_SUCCESS_USE = _AUTH_OK
_ACCOUNT_REF = _ACCOUNT_ID
_EXPLOITISH = _EXPLOIT
_EXEC = _CMD_EXEC
_COLLECT = _FILE_ACCESS


def infer_execution_context(blob: str) -> str:
    """
    Lightweight context for candidate recall only.
    Returns: attacker_local | web_server | target_host | unknown
    """
    if not (blob or "").strip():
        return "unknown"
    # Prefer target/web when both local tooling and in-app exec appear
    if _CTX_WEB_SERVER.search(blob):
        return "web_server"
    if _CTX_TARGET_HOST.search(blob):
        return "target_host"
    if _CTX_ATTACKER_LOCAL.search(blob):
        return "attacker_local"
    return "unknown"


def _blob(action: str, evidence: str) -> str:
    return f"{action or ''}\n{evidence or ''}"


def _step_blob(step: Mapping[str, Any]) -> str:
    return _blob(str(step.get("action") or ""), str(step.get("evidence") or ""))


def _prior_has_account(prior: Sequence[Mapping[str, Any]]) -> bool:
    for s in prior:
        b = _step_blob(s)
        if _ACCOUNT_ID.search(b) or _CRED_OBTAIN.search(b):
            return True
    return False


def _prior_has_cred_obtain(prior: Sequence[Mapping[str, Any]]) -> bool:
    return any(_CRED_OBTAIN.search(_step_blob(s)) for s in prior)


def _expand(tid: str, catalog: set[str]) -> list[str]:
    if tid in catalog:
        return [tid]
    return sorted(c for c in catalog if c.startswith(tid + "."))


def _add(out: list[str], seen: set[str], catalog: set[str], *tids: str, limit: int) -> None:
    for tid in tids:
        for m in _expand(tid, catalog):
            if m not in seen:
                seen.add(m)
                out.append(m)
                if len(out) >= limit:
                    return


# ---------------------------------------------------------------------------
# Behavior-signal layers (each may add candidates; no mutual exclusion)
# ---------------------------------------------------------------------------

def _sig_scanning(blob: str, out: list[str], seen: set[str], catalog: set[str], lim: int) -> None:
    if _SCAN.search(blob) or (_LIGHT_PROBE.search(blob) and _MULTI.search(blob)):
        _add(out, seen, catalog, "T1595", "T1046", limit=lim)


def _sig_alt_auth(blob: str, out: list[str], seen: set[str], catalog: set[str], lim: int) -> None:
    if _ALT_AUTH.search(blob):
        _add(out, seen, catalog, "T1550", limit=lim)


def _sig_auth_cred_use(
    blob: str,
    prior: Sequence[Mapping[str, Any]],
    out: list[str],
    seen: set[str],
    catalog: set[str],
    lim: int,
) -> None:
    """Valid-account use / credential obtain — high recall; gate decides retain."""
    if _AUTH_FAIL_OR_SURFACE.search(blob) and not _AUTH_OK.search(blob):
        # login form / fail alone
        pass
    elif _AUTH_FAIL_OR_SURFACE.search(blob) and re.search(
        r"(?i)\b(authentication|login)\s+fail", blob
    ):
        pass
    elif _AUTH_OK.search(blob) and not re.search(
        r"(?i)\b(authentication|login)\s+fail", blob
    ):
        # Identity on this step OR prior selected chain step
        if _ACCOUNT_ID.search(blob) or _prior_has_account(prior):
            _add(out, seen, catalog, "T1078", limit=lim)
        # Auth success after prior credential acquisition (even if identity only in prior)
        elif _prior_has_cred_obtain(prior):
            _add(out, seen, catalog, "T1078", limit=lim)

    if _CRED_OBTAIN.search(blob):
        _add(out, seen, catalog, "T1078", limit=lim)
        if _SPRAY.search(blob):
            _add(out, seen, catalog, "T1110", limit=lim)


def _sig_exploitation(blob: str, out: list[str], seen: set[str], catalog: set[str], lim: int) -> None:
    if _EXPLOIT.search(blob):
        _add(out, seen, catalog, "T1190", limit=lim)


def _sig_command_exec(
    blob: str, out: list[str], seen: set[str], catalog: set[str], lim: int
) -> None:
    if not _CMD_EXEC.search(blob):
        return
    ctx = infer_execution_context(blob)
    # Attacker-local automation (bash+curl loops, etc.) ≠ target command execution
    if ctx == "attacker_local":
        return
    # web_server / target_host / unknown+exec signal → recall T1059
    if ctx in ("web_server", "target_host", "unknown"):
        _add(out, seen, catalog, "T1059", limit=lim)


def _sig_file_access(blob: str, out: list[str], seen: set[str], catalog: set[str], lim: int) -> None:
    if not _FILE_ACCESS.search(blob):
        return
    # Local automation that greps HTTP responses ≠ target host file collection
    if infer_execution_context(blob) == "attacker_local":
        return
    _add(out, seen, catalog, "T1005", limit=lim)


def _sig_lateral(blob: str, out: list[str], seen: set[str], catalog: set[str], lim: int) -> None:
    if _REMOTE.search(blob):
        _add(out, seen, catalog, "T1021", limit=lim)


def _sig_transfer(blob: str, out: list[str], seen: set[str], catalog: set[str], lim: int) -> None:
    if _INGRESS.search(blob):
        _add(out, seen, catalog, "T1105", limit=lim)
    if _TOOL_GET.search(blob):
        _add(out, seen, catalog, "T1588", limit=lim)


def _sig_evasion(blob: str, out: list[str], seen: set[str], catalog: set[str], lim: int) -> None:
    if _OBFUSC.search(blob):
        _add(out, seen, catalog, "T1027", limit=lim)


def _sig_c2(blob: str, out: list[str], seen: set[str], catalog: set[str], lim: int) -> None:
    if _C2.search(blob):
        _add(out, seen, catalog, "T1132", limit=lim)


def _sig_account_disc(blob: str, out: list[str], seen: set[str], catalog: set[str], lim: int) -> None:
    if _ACCOUNT_DISC.search(blob):
        _add(out, seen, catalog, "T1087", limit=lim)


def generate_candidates(
    *,
    action: str,
    evidence: str,
    catalog_ids: Iterable[str],
    max_candidates: int = 8,
    prior_selected_steps: Optional[Sequence[Mapping[str, Any]]] = None,
) -> list[str]:
    """
    Return technique-id hypotheses present in catalog.

    prior_selected_steps: earlier *successful-path* steps only (chain_status=selected).
    Used to reconnect credential obtain → use → auth across steps. Never raw traces.
    """
    catalog = set(catalog_ids)
    blob = _blob(action, evidence)
    prior = list(prior_selected_steps or [])
    out: list[str] = []
    seen: set[str] = set()
    lim = max_candidates

    _sig_scanning(blob, out, seen, catalog, lim)
    if len(out) >= lim:
        return out
    _sig_alt_auth(blob, out, seen, catalog, lim)
    if len(out) >= lim:
        return out
    _sig_auth_cred_use(blob, prior, out, seen, catalog, lim)
    if len(out) >= lim:
        return out
    _sig_exploitation(blob, out, seen, catalog, lim)
    if len(out) >= lim:
        return out
    _sig_command_exec(blob, out, seen, catalog, lim)
    if len(out) >= lim:
        return out
    _sig_file_access(blob, out, seen, catalog, lim)
    if len(out) >= lim:
        return out
    _sig_lateral(blob, out, seen, catalog, lim)
    if len(out) >= lim:
        return out
    _sig_transfer(blob, out, seen, catalog, lim)
    if len(out) >= lim:
        return out
    _sig_evasion(blob, out, seen, catalog, lim)
    if len(out) >= lim:
        return out
    _sig_c2(blob, out, seen, catalog, lim)
    if len(out) >= lim:
        return out
    _sig_account_disc(blob, out, seen, catalog, lim)

    return out
