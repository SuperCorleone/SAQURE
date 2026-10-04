# 新 AED 工作流：独立 Domain × 合并 AEDIs

## 背景变化

之前：一个大的 AED domain 文件包含所有漏洞的 action，通过注释/解注释 entry action 控制哪些漏洞激活，planner 在这个大 AED 中自动寻找每个 STRIDE 目标的最优路径。

现在：AED 被拆分为 **136 个独立 domain 文件**（对应 100 个漏洞的利用路径，部分漏洞有多条路径）。planner 对每个 domain 独立运行，最优 AP 的选取在外部完成。

## 文件说明

- **136 个 domain 文件**：`post-proposs/{auto-generated,expert-authored}/CVE-XXXX/APn.pddl`
  - 21 个专家编写的 CVE → 55 个 domain
  - 79 个自动生成的 CVE → 81 个 domain
- **6 个合并 AEDI**：`merged_AEDIs/{spoofing, tampering, repudiation, information_disclosure, denial_of_service, elevation_of_privilege}.pddl`
  - 每个 AEDI 是 100 个 CVE 的 objects 和 init facts 的并集，goal 为单一 STRIDE 目标（如 `(:goal (and (spoofing SEFA)))`）
- **过滤脚本**：`aedi_filter.py`
  - 根据 domain 声明的 types、predicates、functions，从合并 AEDI 中过滤出该 domain 相关的 objects 和 init facts

## 步骤

### 第 1 步：确定当前暴露的漏洞列表

根据当前系统快照，确定哪些 CVE 被暴露。例如在时间点 $T_i$，系统暴露漏洞：{CVE-A, CVE-D, CVE-G, CVE-K, ...}，共 N 个漏洞。

### 第 2 步：选取对应的 domain 文件

将 N 个漏洞映射到对应的 domain 文件。由于部分 CVE 有多条攻击路径（AP1, AP2, ...），所以 domain 数量 M ≥ N。

例如：
- CVE-A → AP1（1 个 domain）
- CVE-D → AP1, AP2（2 个 domain）
- CVE-G → AP1（1 个 domain）
- CVE-K → AP1, AP2, AP3（3 个 domain）
- 合计：N = 4 个 CVE → M = 7 个 domain

### 第 3 步：为每个 domain 过滤 AEDI

对 M 个 domain 中的每一个，分别过滤 6 个 STRIDE AEDI：

```python
for domain_i in M_domains:
    domain_aed = rename_domain_to_aed(domain_i)  # 将 domain name 改为 "AED"
    for stride in [S, T, R, I, D, E]:
        filtered_problem = filter_aedi_for_domain(
            aedi_text=merged_AEDIs[stride],
            domain_text=domain_aed,
            cve_id=domain_i 对应的 CVE-ID
        )
        # filtered_problem 只保留该 domain 的 types/predicates 匹配的 objects 和 init facts
```

### 第 4 步：并行运行 Metric-FF

将每组 (domain, filtered_problem) 送入 Metric-FF。M 个 domain × 6 个 AEDI = M × 6 次 planner 调用，可完全并行。

```python
for domain_i in M_domains:
    for stride in [S, T, R, I, D, E]:
        (solvable, cost, plan) = run_ff(domain_aed_i, filtered_problem_i_stride)
        results.append((cve_id, ap_id, stride, solvable, cost, plan))
```

### 第 5 步：每个 STRIDE 目标选取 cost 最小的 AP

对每个 STRIDE 目标，从所有可解的 AP 中选择 **cost 最小**（= 风险最大）的那个：

```python
for stride in [S, T, R, I, D, E]:
    candidates = [(cve, ap, cost, plan) 
                  for (cve, ap, s, solvable, cost, plan) in results 
                  if s == stride and solvable]
    if candidates:
        best = min(candidates, key=lambda x: x.cost)
```

**举例** — Spoofing (S)：

| CVE | AP | Cost | 是否选中 |
|-----|-----|------|---------|
| CVE-A | AP1 | 32 | **是**（cost 最小） |
| CVE-D | AP1 | 48 | 否 |
| CVE-G | AP1 | 46 | 否 |

→ S 目标使用 CVE-A 的 AP1（cost=32）

T, R, I, D, E 同理，各自独立选取。

### 第 6 步：输出

最终输出 6 条 AP（每个 STRIDE 一条），每条是当前漏洞集下该目标的最小 cost 路径：

| STRIDE 目标 | 选中的 CVE | AP | Cost |
|------------|-----------|-----|------|
| Spoofing | CVE-A | AP1 | 32 |
| Tampering | CVE-D | AP2 | 41 |
| Repudiation | — | — | 无可解 AP |
| Information Disclosure | CVE-K | AP1 | 28 |
| Denial of Service | CVE-G | AP1 | 35 |
| Elevation of Privilege | CVE-A | AP1 | 39 |

注意：同一个 CVE 可能在多个 STRIDE 目标下都是最优的（如上例 CVE-A 同时服务 S 和 E）。

## 与之前方案的主要区别

| 方面 | 之前（单体 AED） | 现在（独立 domain） |
|------|----------------|-------------------|
| Domain | 1 个大 AED 包含所有 action | 136 个独立 domain 文件 |
| 漏洞选择 | 注释/解注释 entry action | 按 CVE 列表选取 domain 文件 |
| Planner 调用 | 1 × 6（1 个 domain × 6 AEDI） | M × 6（M 个 domain × 6 AEDI，并行） |
| 每个 STRIDE 的 AP 选取 | Planner 在单个 AED 中自动寻找最优 | 外部逻辑：所有候选中取 min(cost) |
| 可扩展性 | CVE 增多会导致 grounding 爆炸 | 线性扩展：每个 domain 小，独立运行 |
| 新增 CVE | 需合并到单体 AED（容易冲突） | 直接添加新 domain 文件，无冲突 |
