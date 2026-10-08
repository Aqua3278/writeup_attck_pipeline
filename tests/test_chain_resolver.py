from wap.chain.resolver import merge_task_corpus, resolve_chain_source


XBOW_SNIPPET = """
# XBEN-001 Report

## What Happened: The Full Attack Chain

1. Agent probed SSTI → ruled out
2. IDOR on order API → retrieved other user's data
3. Flag returned from IDOR path

## Raw Session

lots of noise...
"""


GOAD_NARRATIVE = """
# GOAD writeup

## Solve Path

扫描发现域控 → 获取凭据 → Kerberoasting → 横向移动 → 拿到目标文件
Goal achieved. Flag returned.
"""


TRACE_ONLY = """
# Agent run log

## Steps

1. nmap scan host A
2. nmap scan host B
3. smbclient on B succeeded
4. dumped SAM
5. logged in as admin
6. flag_found on target share

- step tool output
- step tool output
- step tool output
- step tool output
- step tool output
- step tool output
- step tool output
- step tool output
""" + ("x" * 900)


EMPTYISH = "short note without structure"


def test_explicit_full_chain_level1():
    d = resolve_chain_source(XBOW_SNIPPET)
    assert d.source == "explicit_full_chain"
    assert "Full Attack Chain" in d.header_matched or "full attack chain" in d.header_matched.lower()
    assert "IDOR" in d.section_text
    # section should not need to swallow entire raw session forever
    assert len(d.section_text) < len(XBOW_SNIPPET) or "Raw Session" not in d.section_text


def test_success_narrative_level2():
    d = resolve_chain_source(GOAD_NARRATIVE)
    assert d.source == "explicit_success_narrative"
    assert "Kerberoasting" in d.section_text or "Solve Path" in d.section_text


def test_recoverable_trace_level3():
    d = resolve_chain_source(TRACE_ONLY)
    assert d.source == "recovered_from_trace"


def test_unresolved_level4():
    d = resolve_chain_source(EMPTYISH)
    assert d.source == "unresolved"


def test_sibling_corpus_can_unlock_full_chain():
    primary = "# session timeline\ncurl /\nffuf ...\n"
    sibling = XBOW_SNIPPET
    corpus = merge_task_corpus(primary, [sibling])
    d = resolve_chain_source(corpus)
    assert d.source == "explicit_full_chain"


def test_no_benchmark_branch_api():
    # resolve_chain_source only takes text — content driven
    assert resolve_chain_source.__code__.co_argcount == 1
