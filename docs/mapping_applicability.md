# ATT&CK 映射适用性标准（首批）

> **文档性质**：区分「MITRE 官方定义」与「本项目 coverage 策略」。  
> **不是**把当前 `rules.py` 行为当作正确标准。  
> 标为 **`TBD`** 的条目须人工确认后，方可写入回归样本的正式 `expected`。  
> **覆盖统计约定**（项目全局）：仅 `retained` 计入 coverage；黄标技术可记录但不可计入（见 README）。

相关实现层（职责，非标准本身）：

| 层 | 职责 |
|----|------|
| `direct_llm.DirectLlmMapper` | 对照全部 retained 技巧定义，单模型开放式识别 supported / uncertain |
| 代码结构校验 | 白名单 technique_id、黄标不可计入 coverage |

---

## T1078 Valid Accounts

### 1. ATT&CK 官方定义（摘要）

Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls on systems and services.

- 来源：https://attack.mitre.org/techniques/T1078/  
- 战术（官方）：Initial Access / Persistence / Privilege Escalation / Defense Evasion 等  
- 子技术：T1078.001–.004  

### 2. 本项目计入 coverage 的条件

在**同一步 hard evidence**（action / evidence / supporting）中，须同时满足：

1. 出现**可核对的账户身份**（如 `user:pass`、`authenticated as X`）；  
2. 出现**明确认证成功**表述（非仅登录页、非仅 HTTP 302/200、非仅 Set-Cookie）；  
3. **不存在**同段明确的认证失败信号（见「不应计入」）。

> 说明：上述 1–3 与当前 Stage-2 硬规则及既有「成功认证」锚点测试一致，作为**已工作共识**写入；是否还要求「同一步凭据获得」见 **TBD-T1078-1**。

### 3. 明确不应计入的情形

- 仅发现/泄露凭据字符串，无认证成功；  
- 认证失败、无效凭据、登录失败；  
- 仅发现登录表单/登录页；  
- 仅有「logged in / 302」等弱状态、无明确成功表述且无账户身份；  
- 用工具名或 `step_type` 倒推。

### 4. 与相邻技术的区别

| 技术 | 区别 |
|------|------|
| **T1110 Brute Force** | 喷洒/爆破过程；成功使用有效账户仍可能另标 T1078（边界见 TBD） |
| **T1550** | 使用哈希/票证/他人会话 cookie 等**替代认证材料**，不是账户口令登录本身 |
| **凭据访问类（发现）** | 发现口令 ≠ Valid Accounts；后者强调**使用合法账户** |

### 5. Stage-1 可以召回的情况（项目策略草案）

允许高召回（仍须经 Stage-2/硬规则）：

- 本步有认证成功信号，且具备身份或先验账户/凭据上下文；  
- 本步有凭据发现/获得信号（即使尚未登录）——**召回 ≠ retained**。

不应召回：仅登录失败表面、仅登录表单（无成功信号）。

### 6. 最终允许 retained 的必要条件

- **已确认**：§2 中的身份 + 成功表述 + 无失败信号。  
- **TBD**：是否还必须满足 prompt 中的「凭据获得/发现/喷洒」同一步条件（见争议）。

### 7. 尚需人工确认（TBD）

| ID | 待决问题 |
|----|----------|
| **TBD-T1078-1** | Stage-2 prompt 要求「凭据获得 AND 认证成功」；硬规则目前不要求同一步 obtain。以哪一侧为准？先验步骤发现的凭据是否算数？ |
| **TBD-T1078-2** | 否定表达（如 `not authenticated`）应一律排除；极性匹配策略属通用机制，标准确认后由机制层修复，**不在本技术下单独打补丁**。 |
| **TBD-T1078-3** | 同段先失败后成功（或相反）时，优先「失败一票否决」还是「最终状态」？ |

---

## T1059 Command and Scripting Interpreter

### 1. ATT&CK 官方定义（摘要）

Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. Commands may run via interactive shells, lure documents, secondary payloads, or remote services.

- 来源：https://attack.mitre.org/techniques/T1059/  
- 战术：Execution  
- 子技术：PowerShell、Unix Shell、Python 等  

### 2. 本项目计入 coverage 的条件

- 证据表明在**目标环境**（受害 Web 应用/主机等）发生命令或脚本解释器执行；  
- 存在可核对的解释器/执行 API 信号（如 `os.popen`、`bash`、`powershell`、`subprocess` 等）及对抗性执行语境；  
- **不是**攻击者本机为发包/枚举而写的自动化 shell。

### 3. 明确不应计入的情形

- 攻击者本机 `bash`/`while` + `curl`/`wget` 循环（本地自动化）；  
- 仅出现 CLI 工具名、无解释器在目标侧执行；  
- 用后续 flag/结果倒推本步执行。

### 4. 与相邻技术的区别

| 技术 | 区别 |
|------|------|
| **T1190** | 利用面向公众应用的弱点取得入口/效果；RCE 常**同时**涉及 T1190 与 T1059 |
| **T1005** | 从本地系统**收集数据**；读文件本身不自动等于解释器执行 |
| **T1105** | 向受害环境**传入工具/文件**，不是解释器执行本身 |

### 5. Stage-1 可以召回的情况

- 存在命令/解释器执行信号，且执行上下文**不是** `attacker_local`；  
- SSTI/`os.popen` 等服务端执行应可召回。

### 6. 最终允许 retained 的必要条件

- 非攻击者本机上下文；  
- hard evidence 含解释器/执行信号；  
- （语义上）构成对抗性执行，而非普通运维叙述——细节见 TBD。

### 7. 尚需人工确认（TBD）

| ID | 待决问题 |
|----|----------|
| **TBD-T1059-1** | 仅 mention `os.system`/`os.popen`、无命令输出/效果时，是否足以 retained？ |
| **TBD-T1059-2** | 上下文标签 `unknown` 且仅有 `bash` 时，默认 excluded 还是交 LLM？ |

---

## T1190 Exploit Public-Facing Application

### 1. ATT&CK 官方定义（摘要）

Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness may be a software bug, glitch, or misconfiguration. Exploited applications are often websites/web servers, but may include other Internet-accessible services.

- 来源：https://attack.mitre.org/techniques/T1190/  
- 战术：Initial Access  

### 2. 本项目计入 coverage 的条件

同一步 hard evidence 须体现**利用并产生可核对的意外效果**，例如：

- RCE / 交互式 shell；  
- **已证明的**越权、IDOR、访问控制绕过（效果可核对，非仅猜测）；  
- 其它可直接引用的利用成功效果。

**不充分**：单独 HTTP 200/302/404；仅发送 payload；仅「vulnerable / 探测」表述。

### 3. 明确不应计入的情形

- 仅状态码或页面可达；  
- 仅投放 payload、无效果证据；  
- 漏洞指纹/探测无利用成功；  
- 将整链最终 flag 倒推到未体现利用效果的步骤。

### 4. 与相邻技术的区别

| 技术 | 区别 |
|------|------|
| **T1059** | 解释器执行；常与成功 RCE 同现，但 T1190 强调**利用公开面弱点** |
| **T1595** | 扫描/枚举不是利用 |
| **T1078** | 合法账户登录不是「利用应用弱点」 |

### 5. Stage-1 可以召回的情况

- 证据含 exploit / SSTI / RCE / 模板注入等利用相关信号时，允许召回。  
- **TBD**：已证 IDOR/XSS 但证据无 `exploit`/`payload` 等字样时，Stage-1 是否必须召回（见争议）。

### 6. 最终允许 retained 的必要条件

- 存在利用成功/越权/RCE 等**效果**证据（项目 prompt 与硬规则共识）；  
- 非仅探测、非仅 payload、非仅 HTTP 状态。

### 7. 尚需人工确认（TBD）

| ID | 待决问题 |
|----|----------|
| **TBD-T1190-1** | 已证存储型/反射型 XSS（如 alert 执行 + 业务影响）是否一律按 T1190 retained？ |
| **TBD-T1190-2** | 已证 IDOR 读到他户数据/FLAG 时，Stage-1 召回词表是否必须覆盖「无 exploit 字样」的步骤？ |
| **TBD-T1190-3** | 「探测有响应但无确认效果」与「效果在下一步」时，本步用 unmatched 还是 excluded？ |

---

## T1595 Active Scanning

### 1. ATT&CK 官方定义（摘要）

Adversaries may execute active reconnaissance scans to gather information for targeting. Active scans probe victim infrastructure via network traffic (unlike passive recon).

- 来源：https://attack.mitre.org/techniques/T1595/  
- 战术：Reconnaissance（PRE）  
- 子技术：Scanning IP Blocks / Vulnerability Scanning / Wordlist Scanning  

### 2. 本项目计入 coverage 的条件

本步 hard evidence 体现**系统化**扫描/枚举，例如：

- 真实扫描器 + 字典/FUZZ/多目标/批量；  
- 或轻量探测工具**且**多目标/批量上下文。

### 3. 明确不应计入的情形

- 单次 GET/POST、单次 `curl`、单页 robots/sitemap、单次认证探测；  
- 仅因「主动发包」或候选 ID 为 T1595 而保留；  
- 用 `step_type=reconnaissance` 倒推。

### 4. 与相邻技术的区别

| 技术 | 区别 |
|------|------|
| **T1046** | 官方偏 Discovery：枚举远程主机/网络上的服务；与主动扫描在工具上常重叠，**项目边界见 TBD-T1046-1** |
| **T1190** | 利用 ≠ 扫描 |

### 5. Stage-1 可以召回的情况

- 扫描器/wordlist/FUZZ/批量枚举信号；  
- 当前实现常同时召回 T1046（策略是否保留见 TBD）。

### 6. 最终允许 retained 的必要条件

- hard evidence 满足系统化扫描信号（非 LLM 理由绕过）。

### 7. 尚需人工确认（TBD）

| ID | 待决问题 |
|----|----------|
| **TBD-T1595-1** | 单目标但超大字典的目录爆破，是否一律 T1595？（倾向是，需书面确认） |
| **TBD-T1595-2** | 与 T1046 同一步双 retained 是否允许，或只保留其一？ |

---

## T1046 Network Service Discovery

### 1. ATT&CK 官方定义（摘要）

Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods include port, vulnerability, and/or wordlist scans.

- 来源：https://attack.mitre.org/techniques/T1046/  
- 战术：Discovery  

### 2. 本项目计入 coverage 的条件

**TBD（整节）**：官方定义与 T1595 在扫描类行为上高度重叠。本项目尚未书面规定：

- Web 目录枚举（ffuf）是否同时计 T1046；  
- 仅内网端口/服务发现才计 T1046；  
- 或 Stage-1 可双召回但 coverage 只计 T1595。

在争议解决前：**不将「当前无专用硬门控」解释为「应当 retained」**。

### 3. 明确不应计入的情形（暂定、待确认）

- 单次业务 HTTP 请求；  
- 与 T1595 相同的「非系统化」反例（若最终决定与 T1595 对齐门控）。

### 4. 与相邻技术的区别

见 T1595 §4；核心待决是 **Reconnaissance(T1595) vs Discovery(T1046)** 在 Web writeup 场景如何切分。

### 5. Stage-1 可以召回的情况

- 实现上常与扫描信号一并召回；是否保持 **TBD-T1046-1**。

### 6. 最终允许 retained 的必要条件

- **TBD**：是否增加与 T1595 同级的硬门控，或显式「无代码门控、仅依赖 LLM + 目录政策」。

### 7. 尚需人工确认（TBD）

| ID | 待决问题 |
|----|----------|
| **TBD-T1046-1** | ffuf/nmap 等步骤：双计 T1595+T1046、只计其一、还是按内网/外网切分？ |
| **TBD-T1046-2** | 若只计 T1595，Stage-1 是否仍应召回 T1046？ |

---

## T1550 Use Alternate Authentication Material

### 1. ATT&CK 官方定义（摘要）

Adversaries may use alternate authentication material — such as password hashes, Kerberos tickets, and application access tokens — to move laterally and bypass normal access controls. Such material is generated after successful authentication and may be stolen; adversaries can authenticate without knowing the plaintext password.

- 来源：https://attack.mitre.org/techniques/T1550/  
- 战术：Lateral Movement（官方主战术；子技术含 Web Session Cookie 等）  
- 子技术：T1550.001–.004  

### 2. 本项目计入 coverage 的条件

- hard evidence 表明使用**窃取/劫持/重放/伪造**的替代认证材料（他人 session、stolen cookie、forged JWT/token、PtH/PtT 等）；  
- **不是**使用者自己登录后携带的正常会话 cookie。

### 3. 明确不应计入的情形

- 仅 `Cookie: session=...` 访问自身已登录资源；  
- 正常登录流程（应考虑 T1078，而非 T1550）；  
- 关键词「cookie」单独出现。

### 4. 与相邻技术的区别

| 技术 | 区别 |
|------|------|
| **T1078** | 使用账户口令/合法账户身份认证 |
| **T1550.004** | 明确滥用**Web 会话 cookie** 等替代材料 |

### 5. Stage-1 可以召回的情况

- steal / hijack / replay / forged / 他人 session 等信号。

### 6. 最终允许 retained 的必要条件

- hard evidence 含窃取/重放/伪造/他人会话等强信号（与项目 prompt 一致）。

### 7. 尚需人工确认（TBD）

| ID | 待决问题 |
|----|----------|
| **TBD-T1550-1** | 自己登录后修改 cookie 中的 user_id 造成 IDOR：算 T1550、T1190，还是两者？ |
| **TBD-T1550-2** | 否定句（`not stolen`）的极性处理走通用机制，确认后统一修。 |

---

## 人工确认清单（汇总）

请优先拍板（阻塞正式 `expected` 与后续机制修复）：

1. **TBD-T1078-1**：同一步是否必须「凭据获得」？  
2. **TBD-T1078-2 / 机制**：否定极性（含 `not authenticated`）的统一策略。  
3. **TBD-T1078-3**：成功/失败证据混杂时的优先序。  
4. **TBD-T1046-1/2**：与 T1595 的 coverage 切分。  
5. **TBD-T1190-1/2**：XSS / IDOR 成功步的 retained 与 Stage-1 召回范围。  
6. **TBD-T1059-1/2**：弱执行信号与 `unknown` 上下文。  
7. **TBD-T1550-1**：会话篡改型 IDOR 的技术归属。

确认结果应回写本节，并将对应 `mapping_cases.yaml` 条目的 `standard_status` 从 `TBD` 改为 `confirmed`，再填写正式 `expected`。
