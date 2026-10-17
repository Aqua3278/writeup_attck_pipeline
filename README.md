# Writeup → Attack Path → ATT&CK Pipeline

可扩展的渗透 Writeup 采集、成功攻击链拆解，以及与**筛选后** ATT&CK 技术清单的映射工具。

技术表（只读，不修改）：

`attck/ATT&CK技巧.xlsx`

- 黄色标记 = **excluded**（可记录，不计入 coverage）
- 未标黄 = **retained**（映射对照目录）

## 流水线概览

```text
crawl → analyze → chain → map → validate → report
```

| 阶段 | 作用 |
|------|------|
| crawl | 按来源适配器拉取 Writeup |
| analyze | LLM 分块提取攻击步骤 |
| chain | 解析成功攻击链（selected / excluded） |
| map | **direct_llm**：对照全部 retained 技巧定义，单模型开放式映射 |
| validate | 结构与弱理由检查 |
| report | 导出单篇 / 全局报告 |

### Map：direct_llm

1. 读取成功链上的有效步骤与全部未标黄技巧定义。  
2. 按 `configs/model.yaml` → `direct_llm.batch_size` 分批扫完全表（分批仅为上下文长度，**不是**检索候选）。  
3. 开放式提示词（`prompts/technique_direct_llm_v1.txt`）：只列出有充分证据的映射，允许空结果。  
4. 代码校验白名单 / 黄标后写入结果。

其它约定：

- 证据分级：`direct` / `inferred` / `mentioned` / `unknown`；`mentioned` 不进攻击步骤。
- `step_type` 为分类字段；`tool_setup` / `data_processing` / `validation` / `observation` 默认不计入覆盖。
- Coverage：仅计 retained，同一 writeup 对同一 technique 最多计 1 次。

## 安装

```bash
cd writeup_attck_pipeline
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

在 `.env` 中配置：

- `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL`（analyze / chain / map 共用）

始终用仓库根目录入口：

```bash
python main.py sources list
```

## 数据源

配置：`configs/sources.yaml`

| source_id | adapter | 说明 |
|-----------|---------|------|
| goad_mayfly | goad | Mayfly GOAD 分类页 |
| xbow_redamon | xbow | RedAmon XBOW wiki（scorecard / walkthrough / sess_decoded） |
| local_samples | local | `data/local_import/**` |

新增来源：在 YAML 增加条目（`web` / `github` / `local`），或实现 `SourceAdapter` 并在 `sources/registry.py` 注册。

## 常用命令

```bash
# 来源与 Writeup
python main.py sources list
python main.py writeups list
python main.py writeups rename-readable

# 采集
python main.py crawl --source local_samples
python main.py crawl --source xbow_redamon --limit 3
python main.py crawl --mode retry

# ATT&CK 表
python main.py load-attck

# 单篇：分析 → 攻击链 → 映射 → 校验 → 报告
python main.py analyze --writeup-id <id>
python main.py chain --writeup-id <id>
python main.py map --writeup-id <id>
python main.py validate --writeup-id <id>
python main.py report --writeup-id <id>

# 完整流水线
python main.py run --source local_samples
python main.py run --all --limit 2
python main.py run --source goad_mayfly --skip-llm   # 只采集 + 载表
```

说明：

- crawl `--mode incremental|full|retry`
- `writeup-id` 支持可读 ID 解析（如 `xbow__xben-001-24__session`）

## 配置要点

| 文件 | 内容 |
|------|------|
| `configs/pipeline.yaml` | DB 路径、`attck_workbook` |
| `configs/model.yaml` | 默认 LLM + `direct_llm` 分批参数 |
| `configs/sources.yaml` | 数据源 |
| `prompts/` | path_extract、chain_*、technique_direct_llm |

## 输出

- SQLite：`data/db/pipeline.sqlite3`
- 原始 / 解析：`data/raw/`、`data/parsed/`
- 导出：`data/exports/`
  - 单篇：`writeups/<id>/report.md`、`technique_mapping.json`、`attack_chain.json` 等
  - 全局：`technique_coverage.csv`、`coverage_evidence.csv`、`report.md`

## 合规

- 遵守 robots.txt、限速、重试；不绕过登录 / 验证码。
- 密钥仅环境变量，不写进代码或日志。
- 采集失败记入 `crawl_failures`；可用 `data/local_import/` + local 适配器兜底。

## 测试

```bash
pytest tests -q
```

## 目录结构

```text
writeup_attck_pipeline/
  attck/                   # ATT&CK技巧.xlsx（黄底=排除）及排除规则说明
  configs/                 # pipeline / model / sources
  prompts/                 # path_extract、chain_*、technique_direct_llm
  src/wap/
    sources/adapters/      # goad, xbow, web, github, local
    crawl/ analyze/ chain/
    mapping/
      direct_llm.py        # 全目录单模型映射
      service.py           # map 入口（别名 DirectMappingService）
    validate/ report/ db/ models/ utils/
  data/                    # db, raw, parsed, exports, local_import
  tests/
  main.py
```

## 已知说明

- XBOW 入口为 scorecard；适配器会继续抓 walkthrough / raw / sess_decoded，优先 GitHub wiki raw。
- 采集失败不伪造正文；Markdown 可放入 `data/local_import/` 导入。
