"""Shared hard-evidence signal matchers for Stage-1 candidate recall only.

These helpers do NOT decide retained/excluded. Final semantic judgment is
performed by multi-model voting (ensemble.py).
"""

from __future__ import annotations

import re

# Auth success phrases — recall aid for T1078 candidates (not a retain gate).
AUTH_SUCCESS_RE = re.compile(
    r"("
    r"authentication\s+succeed(?:ed)?|"
    r"authentication\s+successful|"
    r"successfully\s+authenticated|"
    r"authenticated\s+successfully|"
    r"(?<![A-Za-z])authenticated(?![A-Za-z])|"
    r"login\s+succeed(?:ed)?|"
    r"login\s+successful|"
    r"successfully\s+logged\s*in|"
    r"logged\s*in\s+successfully|"
    r"log\s*in\s+success|"
    r"登录成功|成功登录|认证成功"
    r")",
    re.I,
)

# Command / script interpreter execution signals for T1059 recall.
CMD_INTERPRETER_RE = re.compile(
    r"("
    r"\b(powershell|pwsh|cmd\.exe|bash|zsh)\b|"
    r"(?<![A-Za-z])sh(?![A-Za-z])|"
    r"python\s+-c\b|"
    r"\bos\.popen\b|\bos\.system\b|\bsubprocess\b|"
    r"\bexec\s*\(|\bsystem\s*\(|"
    r"Invoke-Expression|"
    r"command\s+execution|execute\s+command|"
    r"命令执行|执行命令|命令提示符"
    r")",
    re.I,
)

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


def infer_execution_context(blob: str) -> str:
    """
    Lightweight context: attacker_local | web_server | target_host | unknown.
    Used only to avoid recalling T1059/T1005 for obvious attacker-local automation.
    """
    if not (blob or "").strip():
        return "unknown"
    if _CTX_WEB_SERVER.search(blob):
        return "web_server"
    if _CTX_TARGET_HOST.search(blob):
        return "target_host"
    if _CTX_ATTACKER_LOCAL.search(blob):
        return "attacker_local"
    return "unknown"
