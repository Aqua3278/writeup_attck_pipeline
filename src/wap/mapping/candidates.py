from __future__ import annotations

"""Stage-1 candidate generation: high recall, never decides retained.

Candidates are HYPOTHESES only. Plain curl/GET/cookie/password alone
must not flood the verifier with weakly related techniques.
"""

import re
from typing import Iterable

# Strong scan / enum signals → T1595 / T1046
_SCAN_STRONG = re.compile(
    r"("
    r"\b(nmap|masscan|zmap|rustscan|ffuf|gobuster|dirb|dirbuster|"
    r"feroxbuster|wfuzz|dirsearch|nikto|nuclei|wpscan)\b|"
    r"\b(wordlist|seclists)\b|\bFUZZ\b|"
    r"端口扫描|目录枚举|字典\s*(扫描|枚举)|批量\s*(探测|扫描|枚举)|"
    r"auxiliary/scanner/"
    r")",
    re.I,
)
# Multi-target light probes (httpx/whatweb only with batch signals)
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
_CRED_ABUSE = re.compile(
    r"("
    r"password\s*spray|bruteforc|credential\s*stuff|"
    r"default\s*(cred|password|account)|hardcoded|"
    r"found\s+(in\s+)?(comment|source|page)|"
    r"discover(?:ed)?\s+(cred|password|user|account)|"
    r"from\s+comment|in\s+html\s+comment|"
    r"喷洒|爆破|默认口令|注释中发现|硬编码|发现.?密码|发现.?凭据|发现.?账户"
    r")",
    re.I,
)
_LOGINISH = re.compile(r"\b(login|password|log\s*in|sign\s*in|凭据|登录)\b", re.I)
_EXPLOITISH = re.compile(
    r"\b(exploit|ssti|rce|webshell|proxyshell|idor|payload|利用|注入)\b",
    re.I,
)
_EXEC = re.compile(r"\b(powershell|bash|cmd\.exe|python\s+-c|命令执行)\b", re.I)
_INGRESS = re.compile(
    r"\b(wget|curl).{0,60}\.(sh|exe|elf|ps1)\b|\b(upload|上传|ingress)\b",
    re.I,
)
_COLLECT = re.compile(r"\b(/etc/passwd|\bsam\b|ntds|敏感文件|收集数据)\b", re.I)
_REMOTE = re.compile(r"\b(ssh|rdp|winrm|psexec|wmiexec|evil-winrm)\b", re.I)
_OBFUSC = re.compile(r"\b(obfuscat|混淆|绕过.?检测|defender)\b", re.I)
_ENCODE_C2 = re.compile(r"\b(c2|beacon|callback|exfil)\b", re.I)
_TOOL_GET = re.compile(r"\b(git\s+clone|pip\s+install)\b", re.I)
_ACCOUNT_DISC = re.compile(r"\b(userenum|账户发现)\b", re.I)
_SPRAY = re.compile(r"\b(spray|bruteforc|喷洒|爆破)\b", re.I)


def _expand(tid: str, catalog: set[str]) -> list[str]:
    if tid in catalog:
        return [tid]
    return sorted(c for c in catalog if c.startswith(tid + "."))


def _add(out: list[str], seen: set[str], catalog: set[str], *tids: str, limit: int) -> bool:
    for tid in tids:
        for m in _expand(tid, catalog):
            if m not in seen:
                seen.add(m)
                out.append(m)
                if len(out) >= limit:
                    return True
    return False


def generate_candidates(
    *,
    action: str,
    evidence: str,
    catalog_ids: Iterable[str],
    max_candidates: int = 6,
) -> list[str]:
    """
    Return technique-id hypotheses present in catalog.
    Intentionally does NOT map plain curl/GET/cookie/password → high-risk IDs
    unless stronger co-signals appear (still never decides retained).
    """
    catalog = set(catalog_ids)
    blob = f"{action}\n{evidence}"
    out: list[str] = []
    seen: set[str] = set()
    lim = max_candidates

    if _SCAN_STRONG.search(blob) or (_LIGHT_PROBE.search(blob) and _MULTI.search(blob)):
        if _add(out, seen, catalog, "T1595", "T1046", limit=lim):
            return out

    if _ALT_AUTH.search(blob):
        if _add(out, seen, catalog, "T1550", limit=lim):
            return out

    if _CRED_ABUSE.search(blob):
        if _add(out, seen, catalog, "T1078", limit=lim):
            return out
        if _SPRAY.search(blob) and _add(out, seen, catalog, "T1110", limit=lim):
            return out
    elif _LOGINISH.search(blob) and _CRED_ABUSE.search(blob):
        if _add(out, seen, catalog, "T1078", limit=lim):
            return out
    # plain login/password string alone → no T1078 candidate (gate would reject anyway;
    # omitting reduces LLM acceptance bias)

    if _EXPLOITISH.search(blob):
        if _add(out, seen, catalog, "T1190", limit=lim):
            return out
        if _EXEC.search(blob) and _add(out, seen, catalog, "T1059", limit=lim):
            return out

    if _EXEC.search(blob) and _add(out, seen, catalog, "T1059", limit=lim):
        return out
    if _INGRESS.search(blob) and _add(out, seen, catalog, "T1105", limit=lim):
        return out
    if _COLLECT.search(blob) and _add(out, seen, catalog, "T1005", limit=lim):
        return out
    if _REMOTE.search(blob) and _add(out, seen, catalog, "T1021", limit=lim):
        return out
    if _OBFUSC.search(blob) and _add(out, seen, catalog, "T1027", limit=lim):
        return out
    if _ENCODE_C2.search(blob) and _add(out, seen, catalog, "T1132", limit=lim):
        return out
    if _TOOL_GET.search(blob) and _add(out, seen, catalog, "T1588", limit=lim):
        return out
    if _ACCOUNT_DISC.search(blob) and _add(out, seen, catalog, "T1087", limit=lim):
        return out

    # Plain HTTP / cookie / password with no stronger signal → empty candidates
    # (Stage-2 unmatched). This is intentional: unmatched > forced mapping.
    return out
