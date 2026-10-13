# Writeup → Attack Path → ATT&CK Pipeline

可扩展的渗透 Writeup 采集、成功攻击链拆解，以及与**筛选后** ATT&CK 技术清单的映射工具。

技术表（只读，不修改）：

`../benchmark/templates/ATT&CK技巧.xlsx`

- 黄色标记 = **excluded**（可记录，不计入 coverage）
- 未标黄 = **retained**（Stage-1 候选池）

## 流水线概览

```text
crawl → analyze → chain → map → validate → report
```

| 阶段 | 作用 |
|------|------|
| crawl | 按来源适配器拉取 Writeup |
| analyze | LLM 分块提取攻击步骤 |
| chain | 解析成功攻击链（selected / excluded） |
| map | Stage-1 语义向量候选 → A/B/C 多模型投票 |
| validate | 结构与弱理由检查 |
| report | 导出单篇 / 全局报告 |

### Map：候选 + 投票

1. **Stage-1（代码）**：用 **BAAI/bge-m3** 对当前 step 与全部 retained 技巧做稠密检索，取 Top-K（默认 10）。  
   - Doc 向量按技巧表指纹缓存到 `data/cache/embeddings/`，换题通常不必重建。  
   - Query 向量按每个 step 现场编码。
2. **Stage-2（模型）**：A/B 独立判断每个候选 `support|reject|insufficient`；分歧或不足时由 C 裁决。  
   - 代码只做结构校验（候选集、黄标、每步 retained 上限等）。  
   - 禁止仅凭工具名 / 关键词 / `step_type` / 后续结果直接 retain。

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

- 默认 LLM（analyze / chain）：`LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL`
- 映射投票 A/B/C：`MAP_MODEL_*`、`MAP_BASE_URL_*`、对应 API Key（见 `.env.example`）

首次跑 `map` 会从 Hugging Face 拉取 **BGE-M3**（需网络；权重较大，CPU 推理偏慢）。

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

# Stage-1 向量召回评估（mapping_cases gold；可选全表）
python main.py eval-candidates --with-full-catalog
```

说明：

- crawl `--mode incremental|full|retry`
- `analyze` / `map` / `chain` 支持 `--offline`（启发式，仅联调，不能替代正式 LLM）
- `writeup-id` 支持可读 ID 解析（如 `xbow__xben-001-24__session`）

## 配置要点

| 文件 | 内容 |
|------|------|
| `configs/pipeline.yaml` | DB 路径、ATT&CK 表、候选 `strategy: vector`、BGE-M3、Top-K |
| `configs/model.yaml` | 默认 LLM + ensemble A/B/C |
| `configs/sources.yaml` | 数据源 |
| `prompts/` | 路径提取、攻击链、技术投票提示词 |

## 输出

- SQLite：`data/db/pipeline.sqlite3`
- 原始 / 解析：`data/raw/`、`data/parsed/`
- 向量缓存：`data/cache/embeddings/`
- 导出：`data/exports/`
  - 单篇：`writeups/<id>/report.md`、`technique_mapping.json`、`attack_chain.json` 等
  - 全局：`technique_coverage.csv`、`coverage_evidence.csv`、`report.md`
  - 候选评估：`candidate_eval/compare_vector.json`

报告中 Step 与 ATT&CK 绑定；含候选集、A/B/C 立场与中文理由；文末列出未进入 retained 的 `pending_review`（带 Step 指针）。

## 合规

- 遵守 robots.txt、限速、重试；不绕过登录 / 验证码。
- 密钥仅环境变量，不写进代码或日志。
- 采集失败记入 `crawl_failures`；可用 `data/local_import/` + local 适配器兜底。

## 测试

```bash
pytest tests -q
```

夹具：`tests/fixtures/mapping_cases.yaml`（向量召回评估用 confirmed 标签）。

## 目录结构

```text
writeup_attck_pipeline/
  configs/                 # pipeline / model / sources
  prompts/                 # path_extract、chain_*、technique_ensemble
  src/wap/
    sources/adapters/      # goad, xbow, web, github, local
    crawl/ analyze/ chain/
    mapping/
      candidate/           # embedding, vector_index, vector_gen, evaluate
      ensemble.py          # A/B/C 投票
      service.py           # map 编排
    validate/ report/ db/ models/ utils/
  data/                    # db, raw, parsed, cache, exports, local_import
  tests/
  main.py
```

## 已知说明

- XBOW 入口为 scorecard；适配器会继续抓 walkthrough / raw / sess_decoded，优先 GitHub wiki raw。
- 采集失败不伪造正文；Markdown 可放入 `data/local_import/` 导入。
- 换 ATT&CK 表内容或换 embedding 模型后，会按指纹重建 doc 向量缓存。
