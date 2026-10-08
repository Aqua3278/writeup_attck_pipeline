"""Unified ATT&CK display metadata. LLM must NOT invent names/tactics."""

from __future__ import annotations

import json
import re
from pathlib import Path

from wap.models.schemas import TechniqueRef
from wap.utils.config import ROOT

# Official-ish Chinese labels for common ATT&CK tactics / techniques.
# Fallback: keep English name from catalog.
TACTIC_ZH: dict[str, str] = {
    "Reconnaissance": "侦察",
    "Resource Development": "资源开发",
    "Initial Access": "初始访问",
    "Execution": "执行",
    "Persistence": "持久化",
    "Privilege Escalation": "权限提升",
    "Defense Evasion": "防御规避",
    "Credential Access": "凭据访问",
    "Discovery": "发现",
    "Lateral Movement": "横向移动",
    "Collection": "收集",
    "Command and Control": "命令与控制",
    "Exfiltration": "数据渗出",
    "Impact": "影响",
}

TECHNIQUE_ZH: dict[str, str] = {
    "T1595": "主动扫描",
    "T1592": "收集受害主机信息",
    "T1589": "收集受害者身份信息",
    "T1590": "收集受害者网络信息",
    "T1596": "搜索开放技术数据库",
    "T1593": "搜索开放网站/域名",
    "T1594": "搜索受害者自有网站",
    "T1588": "获取能力",
    "T1608": "准备能力",
    "T1190": "利用面向公众的应用程序",
    "T1133": "外部远程服务",
    "T1199": "可信关系",
    "T1078": "有效账户",
    "T1059": "命令与脚本解释器",
    "T1047": "Windows 管理规范",
    "T1569": "系统服务",
    "T1072": "软件部署工具",
    "T1098": "账户操纵",
    "T1547": "启动或登录自动执行",
    "T1136": "创建账户",
    "T1543": "创建或修改系统进程",
    "T1546": "事件触发执行",
    "T1505": "服务器软件组件",
    "T1548": "滥用提升控制机制",
    "T1134": "访问令牌操纵",
    "T1068": "利用漏洞提升权限",
    "T1140": "去混淆/解码文件或信息",
    "T1564": "隐藏工件",
    "T1070": "指标清除",
    "T1036": "伪装",
    "T1027": "混淆文件或信息",
    "T1218": "系统二进制代理执行",
    "T1562": "削弱防御",
    "T1112": "修改注册表",
    "T1110": "暴力破解",
    "T1555": "从密码存储获取凭据",
    "T1003": "操作系统凭据转储",
    "T1558": "窃取或伪造 Kerberos 票据",
    "T1552": "未保护的凭据",
    "T1087": "账户发现",
    "T1083": "文件与目录发现",
    "T1046": "网络服务发现",
    "T1135": "网络共享发现",
    "T1018": "远程系统发现",
    "T1082": "系统信息发现",
    "T1016": "系统网络配置发现",
    "T1049": "系统网络连接发现",
    "T1033": "系统所有者/用户发现",
    "T1007": "系统服务发现",
    "T1210": "利用远程服务",
    "T1570": "横向工具传输",
    "T1021": "远程服务",
    "T1550": "使用备用身份验证材料",
    "T1560": "归档收集的数据",
    "T1005": "从本地系统收集数据",
    "T1114": "电子邮件收集",
    "T1071": "应用层协议",
    "T1132": "数据编码",
    "T1105": "入口工具传输",
    "T1090": "代理",
    "T1219": "远程访问软件",
    "T1041": "通过 C2 通道渗出",
    "T1048": "通过备用协议渗出",
}


def tactic_en(raw: str) -> str:
    s = (raw or "").strip()
    # Excel often: "Discovery 环境发现"
    m = re.match(r"^([A-Za-z][A-Za-z /&-]+)", s)
    if m:
        return m.group(1).strip()
    return s


def tactic_zh(raw: str) -> str:
    en = tactic_en(raw)
    if en in TACTIC_ZH:
        return TACTIC_ZH[en]
    # trailing Chinese already in Excel
    m = re.search(r"[\u4e00-\u9fff].+$", raw or "")
    if m:
        return m.group(0).strip()
    return en or raw or ""


def technique_zh(technique_id: str, technique_name_en: str = "") -> str:
    base = (technique_id or "").split(".")[0].split("-")[0]
    if technique_id in TECHNIQUE_ZH:
        return TECHNIQUE_ZH[technique_id]
    if base in TECHNIQUE_ZH:
        return TECHNIQUE_ZH[base]
    return technique_name_en or technique_id


def enrich_ref(t: TechniqueRef) -> TechniqueRef:
    t.technique_name_en = t.technique_name
    t.technique_name_zh = technique_zh(t.technique_id, t.technique_name)
    t.tactic_en = tactic_en(t.tactic)
    t.tactic_zh = tactic_zh(t.tactic)
    return t


def display_technique(tid: str, name_en: str = "", name_zh: str = "") -> str:
    zh = name_zh or technique_zh(tid, name_en)
    return f"{tid} {zh}"


def export_metadata_json(techs: list[TechniqueRef], path: Path | str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for t in techs:
        enrich_ref(t)
        rows.append(
            {
                "technique_id": t.technique_id,
                "technique_name_en": t.technique_name_en or t.technique_name,
                "technique_name_zh": t.technique_name_zh,
                "tactic_en": t.tactic_en or tactic_en(t.tactic),
                "tactic_zh": t.tactic_zh or tactic_zh(t.tactic),
                "description": t.description,
                "catalog_retained": t.retained,
            }
        )
    p.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


# Classification-only: these steps are kept in the path but default to unmatched
# for coverage (not "step_type → technique" mapping).
NON_COVERAGE_STEP_TYPES = frozenset(
    {"tool_setup", "data_processing", "validation", "observation"}
)

PHASE_ORDER = [
    "侦察",
    "账户/凭据获取",
    "初始访问",
    "执行",
    "权限提升",
    "持久化",
    "防御规避",
    "发现",
    "横向移动",
    "收集",
    "命令与控制",
    "其他",
]

VALID_STEP_TYPES = frozenset(
    {
        "attack",
        "reconnaissance",
        "credential_access",
        "exploitation",
        "execution",
        "persistence",
        "defense_evasion",
        "lateral_movement",
        "collection",
        "discovery",
        "tool_setup",
        "data_processing",
        "validation",
        "observation",
        "other",
    }
)

VALID_PHASES = frozenset(PHASE_ORDER)


def default_metadata_path() -> Path:
    return ROOT / "data" / "exports" / "attck_metadata.json"
