# Writeup → Attack Path → ATT&CK Pipeline

可扩展的渗透 Writeup 采集、攻击路径拆解、与**筛选后** ATT&CK 技术清单映射工具。

技术表默认读取（只读，不修改）：

`../benchmark/templates/ATT&CK技巧.xlsx`

- 黄色标记的技术 = **excluded**（可记录命中，不计入核心覆盖率）
- 未标黄 = **retained**

## 设计要点

1. **采集适配器可插拔**：新增来源只需加 YAML + adapter，不改分析/映射核心。
2. **分阶段解耦**：crawl → analyze → map → validate → report，可单独运行。
3. **LLM 不分整篇硬塞**：按段落/chunk 提取步骤，再逐步映射。
4. **证据分级**：`direct` / `inferred` / `mentioned` / `unknown`；`mentioned` 不进入攻击步骤。
5. **证据驱动映射（核心）**：Evidence → 行为 → ATT&CK 定义 → 必要条件 → retained。准确率优先于覆盖率。
6. **两阶段映射**：Stage-1 候选（高召回，代码侧）→ Stage-2 验证（高精确，LLM + 代码门控）。禁止工具名/关键词/`step_type`/结果倒推直接 retained。
7. **行为级 Step**：合并连续同类 HTTP 探测；action 不得超过 evidence；区分 observation / attack / setup。
8. **step_type**：分类字段；`tool_setup` / `data_processing` / `validation` / `observation` 默认不计入覆盖。
9. **人读报告**：Step↔ATT&CK 绑定；短理由；中文名来自固定 metadata。
10. **覆盖统计**：只计 retained；writeup 内去重；`coverage_evidence.csv` 可追溯。

## 安装

```bash
cd writeup_attck_pipeline
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env   # 填入 LLM_API_KEY（分析/映射需要）
```

将 `src` 加入路径，或始终用仓库根目录的 `main.py`：

```bash
python main.py sources list
```

## 数据源

配置：`configs/sources.yaml`

| source_id | adapter | 说明 |
|-----------|---------|------|
| goad_mayfly | goad | https://mayfly277.github.io/categories/goad/ |
| xbow_redamon | xbow | RedAmon XBOW wiki scorecard + walkthrough/raw |
| local_samples | local | `data/local_import/**` |

新增来源示例：增加 YAML 条目，`adapter_type` 选 `web` / `github` / `local`，或实现 `SourceAdapter` 并在 `sources/registry.py` 注册。

## 命令

```bash
# 查看来源
python main.py sources list

# 采集（可限量冒烟）
python main.py crawl --source local_samples
python main.py crawl --source goad_mayfly --limit 2
python main.py crawl --source xbow_redamon --limit 3

# 加载 ATT&CK 表
python main.py load-attck

# 路径拆解 / 映射 / 校验（需 LLM）
python main.py analyze --writeup-id <id>
python main.py map --writeup-id <id>
python main.py validate --writeup-id <id>

# 报告
python main.py report

# 完整流水线（采集+分析+映射+报告）
python main.py run --source local_samples
python main.py run --all --limit 2          # 限量联调
python main.py run --source goad_mayfly --skip-llm   # 只采集+载表
```

运行模式概念：

- crawl `--mode incremental|full|retry`
- `analyze` / `map`：对已落盘 Writeup 重跑（map 会重新读 Excel）
- `writeups list` / `writeups rename-readable`：可读 ID

## 输出

- SQLite：`data/db/pipeline.sqlite3`
- 原始/解析：`data/raw/`, `data/parsed/`
- 导出：`data/exports/`
  - 单篇：`writeups/<id>/report.md`（Step↔ATT&CK 绑定）、`technique_mapping.json`
  - 全局：`technique_coverage.csv`、`coverage_evidence.csv`、`report.md`

覆盖单位：每个 writeup 对每个 technique **最多计 1 次**（仅 retained）。

## 合规

- 遵守 robots.txt、限速、重试；不绕过登录/验证码。
- 密钥仅环境变量；不写进代码或日志。
- 采集失败会记入 `crawl_failures`，可用本地 Markdown 导入兜底。

## 无 LLM 时的离线冒烟（仅联调）

当前环境若未配置 `LLM_API_KEY`，可用启发式模式跑通「步骤→映射→报告」（**不能替代**正式 LLM 分析）：

```bash
python main.py analyze --source local_samples --offline
python main.py map --source local_samples --offline
python main.py validate --source local_samples
python main.py report
```

正式研究请配置 `.env` 后去掉 `--offline`，走分块 LLM 提取与映射。

## 测试

```bash
pytest tests -q
```

## 目录结构

```
writeup_attck_pipeline/
  configs/           # sources.yaml, model.yaml, pipeline.yaml
  prompts/           # path_extract_v2, technique_verify_v2
  src/wap/
    sources/adapters/  # goad, xbow, web, github, local
    crawl/ analyze/ mapping/ validate/ report/
    db/ models/ utils/
  data/local_import/ # 本地 Markdown 导入
  tests/
  main.py
```

## 已知说明

- 技术表路径指向 `benchmark/templates/ATT&CK技巧.xlsx`（仓库中无 `(1)` 后缀文件名时以实际文件为准）。
- XBOW 入口为 scorecard；适配器会继续抓 `walkthrough`/`raw`/`sess_decoded` 链接，优先尝试 GitHub wiki raw。
- 采集失败不会伪造正文；可把 Markdown 放进 `data/local_import/` 用 `local` 适配器导入。
