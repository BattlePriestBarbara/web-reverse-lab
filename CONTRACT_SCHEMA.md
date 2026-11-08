# `contract.json` Schema v2 与多源融合规则

> 一句话：v1 回答"**发生过什么**"，v2 还要回答"**应当是什么**"以及"**这条结论凭什么**"。
> 三个问题的答案分别落在 `observed_*` / `declared` / `provenance` 三层，层与层之间
> **不允许互相覆盖**。

实现只有一个真源：`collectors/contract_schema.py`。本文件是它的设计说明，
代码是可执行版本；两者冲突时以代码 + `scripts/selftest_contract_schema.py`
的 51 条断言为准（断言覆盖了下面每一条规则）。

---

## 1. 为什么必须升级

P2 的契约（`schema_version: 1`）只记录观测事实：`statuses`、`content_types`、
`params[].observed_values`、`auth.schemes`。它对 L3–L6 有一处硬伤——**回答不了"应当"**：

| 下游要问的问题 | v1 的答案 | 后果 |
| --- | --- | --- |
| 这个参数必填吗？类型是什么？ | 只有 `observed_values` 样本 | 生成的请求要么缺参要么类型错，fuzz 全是噪音 |
| 这个端点要 Bearer 还是 Cookie？ | 只有"这次带了什么" | 鉴权矩阵（L4）无从建表 |
| spec 里有、本次没调用的端点，是废弃了还是没人碰？ | 查不到 | 漏掉真实端点，或把废弃端点当漏洞入口 |
| 这条结论是从哪来的？ | 有 `evidence_ref`，但**没有"来源"概念** | 分不清"文档说"和"我看见了" |

v2 的解法不是加字段，而是**把三类信息拆进三个互不覆盖的层**：

```
declared  声明层   OpenAPI / Swagger：应当怎样（parameters / security / responses.schema）
observed  观测层   HAR + flows JSONL：实际上怎样（observed_statuses / observed_security / observed_values）
verdict   结论层   由上面两层按固定规则推出（status / contradictions）
```

---

## 2. 端点字段

| 字段 | 类型 | 来源 | 说明 |
| --- | --- | --- | --- |
| `id` | string | 融合器分配 | `ep_0001`…，按 `(path, method)` 排序编号 |
| `method` | string | 两轨 | 大写 |
| `path` | string | 声明轨优先 | 融合后展示 OpenAPI 的 `{id}` 形式；观测轨的 `{int}` 形式存 `path_observed_template` |
| `path_samples` | string[] | 观测轨 | 真实出现过的具体路径（≤20），用于回放与 L4 越权枚举 |
| `kind` | string | 观测轨 | `api`/`document`/`static`/`other`（按 MIME 判，不由声明猜） |
| `parameters[]` | object[] | 声明为主、观测补值 | 见 §3 |
| `security` | object | 声明为主、观测对账 | `{declared[], required, source}` |
| `responses` | object | 两轨分别写 | `{"200": {description, schema, source, declared, observed_hits, undeclared}}` |
| `observed_statuses` | int[] | 观测轨 | 实测状态码（v1 的 `statuses` 升级而来） |
| `observed_security` | object | 观测轨 | `{schemes[], statuses_without_credentials[], required}` |
| `status` | enum | 结论层 | `active`/`deprecated`/`unverified`/`hidden`/`unknown` |
| `spa_shell` | bool | 观测轨 | 响应体与 catch-all 众数哈希相同 → 200 不代表资源存在 |
| `deprecated` | bool | 声明轨 | OpenAPI 的 `deprecated: true` |
| `provenance` | string[] | 两轨 | **审计基石**：`["OPENAPI", "HAR_SEQ_65"]` |
| `provenance_detail` | object | 两轨 | 每个 tag → 可追溯元信息（spec 路径 / run_id / phase / ref） |
| `contradictions[]` | object[] | 结论层 | `{field, declared, observed, note}`，声明与实测冲突 |
| `evidence_ref` | string[] | 观测轨 | `har/<run>.har#entry-N` 与 `flows/<run>.jsonl#seq-N` |
| `client_algo` | string[] | 观测轨 | 前端算法线索（L3 入口） |
| `discovery` | object | 观测轨 | `first_ts`/`first_client`/`clients`/`phase`/`phases`/`hits` |
| `notes` | string[] | 结论层 | 无法定论但要留痕（如"声明要鉴权但未观测到凭据头"） |

### provenance tag 规范

| tag | 含义 | 可回链到 |
| --- | --- | --- |
| `OPENAPI` | 该端点在 OpenAPI 文档中声明过 | `provenance_detail.OPENAPI.spec` |
| `HAR_SEQ_<n>` | 该端点有一条实测交换落在 flows 第 n 行 | `flows/<run>.jsonl#seq-<n>`（最优锚点） |
| `HAR` | 来自 HAR 但没有单行锚点（证据降级，必须显式可见） | `har/<run>.har` |
| `CRAWL`/`REPLAY`/`JS_STATIC`/`PROFILE`/`BASELINE` | 其他证据轨 | 各自 detail |

> `provenance` 为空 = 端点不可入库。这是**唯一一条会让校验器返回非 0 的结构错误**
> （不是 warning）：没有来源的端点进了契约，L5 报出的漏洞就无法回证。

---

## 3. `parameters` 字段

```jsonc
{
  "name": "id",                  // 规范名（声明侧优先）
  "name_aliases": ["{int}"],     // 观测侧的写法，保留以免丢信息
  "in": "path",                  // path | query | header | cookie | body
  "required": true,              // 声明优先；观测永不反推（R3）
  "schema": {"type": "integer", "format": "int64"},
  "description": "产品 id",
  "source": "OPENAPI",           // 该参数的"应当"来自哪一轨
  "observed_values": ["1", "2"]  // 观测样本（只记 query/path；body 只记字段名）
}
```

---

## 4. 融合规则（R1–R9）

| # | 规则 | 为什么必须这样 |
| --- | --- | --- |
| **R1** | 路径按**段签名**匹配，占位符互通：`{int}` = `{id}` = 任意单段 | HAR 模板化出 `{int}`，OpenAPI 写 `{id}`。按字符串精确匹配 → 多源重合度恒为 0，融合形同虚设 |
| **R2** | 尾斜杠归一（`/api-docs/` = `/api-docs`）；**大小写敏感**（`/api/Products` ≠ `/api/products`） | 前者是同一资源；后者在 Express 里真是两个路由，强行归并会把两条端点合成一条 |
| **R3** | `required`/`schema` 只能由**声明**给出；观测只加 `observed_values` | "这次没传 `q`" ≠ "`q` 非必填"。把没观测到记成非必填，下游就会理直气壮地漏参 |
| **R4** | `path` 参数按**段下标**配对，合并后保留声明侧名字，观测侧写法进 `name_aliases` | 同位置的同一个参数不该出现两次（`{int}` 与 `id` 各占一条） |
| **R5** | `responses` 同状态码下：声明补 `schema`/`description`，观测补 `observed_hits`；实测出现而声明没有的状态码标 `undeclared: true` 并记冲突 | `undeclared` 的状态码往往是错误分支、权限位或调试口子——L5 最好的入口线索 |
| **R6** | 鉴权：声明 `required` 优先，但与实测冲突时**记 `contradictions`，不静默选边** | 声明要鉴权而实测免认证放行 = 越权线索；声明免鉴权而实测 401 = 声明过期。两种都得人工看 |
| **R7** | 活性由 `decide_status` **单点**判定，见 §5 | 各脚本各写一套口径，最后一定互相矛盾 |
| **R8** | v1 → v2 升级只搬运事实，不做推断 | 读旧文件时顺手猜一把，是最难查的一类 bug |
| **R9** | 校验器永不抛异常，错误与警告分开返回 | 3 个端点不合格不该让另外 65 个也进不了下游；但错误必须显式列出 |

**不变式（Invariants）**

1. 融合不丢弃任何一侧的信息：`merge_into` 只有并集与"补空"，没有删除分支。
2. 任何"声明 vs 实测"的不一致都进 `contradictions`，且**下游评估脚本必须把它单列一栏**。
3. `spa_shell: true` 的端点永远不进存活统计，也不进召回率分子。

---

## 5. `status` 判定表

| 声明轨有? | 实测有? | 其它条件 | status |
| --- | --- | --- | --- |
| 任意 | 任意 | `spa_shell: true` | `unknown`（200 ≠ 存在） |
| 是 | 任意 | `deprecated: true` | `deprecated`（声明优先；实测仍可调用另记） |
| 是 | 是 | — | `active` |
| 是 | 否 | — | `unverified`（声明过、没观测到：可能废弃，也可能只在后台用） |
| 否 | 是 | **存在**声明轨 | `hidden`（未声明表面 —— 情报重点） |
| 否 | 是 | 无声明轨（纯 HAR 契约，如 P2） | `active`（"未声明"要相对于一份声明才成立） |
| 否 | 否 | — | `unknown` |

> **交叉验证（实测）**：把 P2 的真实契约（68 端点）升级到 v2 后，`status=unknown` 的集合与
> `spa_shell=true` 的集合**完全相等**（都是那 19 个 catch-all 壳），49 个真实端点全部
> `active`。换靶场后若这两个数不等，先查 `spa_shell` 判定，而不是查状态机。

---

## 6. 融合后的完整示例

```jsonc
{
  "id": "ep_0117",
  "method": "GET",
  "path": "/rest/products/{id}/reviews",          // 声明轨的规范形式
  "path_observed_template": "/rest/products/{int}/reviews",
  "path_samples": ["/rest/products/1/reviews", "/rest/products/2/reviews"],
  "kind": "api",
  "parameters": [
    {"name": "id", "in": "path", "required": true, "name_aliases": ["{int}"],
     "schema": {"type": "integer"}, "source": "OPENAPI", "observed_values": ["1", "2"]},
    {"name": "q", "in": "query", "required": null, "source": "HAR",
     "observed_values": ["apple"]}          // 声明没提这个参数 -> required 留 null
  ],
  "security": {"declared": [], "required": false, "source": "OPENAPI"},
  "observed_security": {"schemes": [], "statuses_without_credentials": [], "required": null},
  "responses": {
    "200": {"description": "OK", "schema": {"type": "array"}, "source": "OPENAPI",
            "declared": true, "observed_hits": 2},
    "401": {"source": "HAR", "observed_hits": 1, "undeclared": true}
  },
  "observed_statuses": [200, 401],
  "status": "active",
  "spa_shell": false,
  "deprecated": false,
  "provenance": ["OPENAPI", "HAR_SEQ_65"],
  "provenance_detail": {
    "OPENAPI": {"track": "OPENAPI", "spec": "sources/swagger.json",
                "operation_id": "getProductReviews"},
    "HAR_SEQ_65": {"track": "HAR", "ref": "flows/p3_headless.jsonl#seq-65",
                   "phase": "headless", "run_id": "p3_headless"}
  },
  "contradictions": [
    {"field": "responses.401", "declared": null, "observed": 401,
     "note": "实测返回了声明里没有的状态码（可能是错误分支、权限位或调试口子）"}
  ],
  "evidence_ref": ["har/p3_headless.har#entry-12",
                   "flows/p3_headless.jsonl#seq-65"],
  "sources_detail": {"tracks": ["OPENAPI", "HAR"], "declared": true,
                     "observed": true, "multi_source": true}
}
```

---

## 7. 怎么验证

```powershell
# 1) 规则自检（纯离线，不碰靶场、不碰 docker）：51 条断言，覆盖 R1-R9
python scripts\selftest_contract_schema.py
# 期望：[ok] contract_schema 自检全部通过（51 断言）   退出码 0

# 2) 用 P2 的真实契约验证"v1 能无损升级"：68 端点、结构零错误
python collectors\contract_schema.py --validate contracts\contract_p2_final.json --stats
# 期望：status: active=49, unknown=19；provenance: HAR_SEQ_*=68；[ok] 结构校验通过

# 3) 人工抽查 v2 记录（字段是否齐全、provenance 是否可回链）
python collectors\contract_schema.py --validate contracts\contract_p2_final.json ^
    --dump-upgraded contracts\contract_p2_final.v2.json --stats
```

---

## 8. 向后兼容与迁移

* `schema_version: 1` 的文件**不需要重跑**：`normalize_contract()` 现场升级，
  产物里留 `upgraded_from_schema_version: 1`，审计时能看出是迁移来的。
* `har_to_contract.py` 目前仍产出 v1（P2 验收脚本依赖它），P3 Step 3 会把观测轨
  切到 v2 并直接写 `provenance` / `responses.observed_hits`。
* `scripts/verify_p2_baseline.py` 已改为同时认 `observed_statuses` 与 v1 的 `statuses`，
  两种契约都能跑，P2 报告可随时复现。

## 9. P3 各 Step 的落点

| Step | 产出 | 依赖本文件的 |
| --- | --- | --- |
| 1（本次） | `collectors/contract_schema.py` + 本文件 + 自检 | — |
| 2 | `scripts/parse_openapi.py` → `contract_openapi.json`（`$ref` 内联） | §2/§3 字段、R3 |
| 3 | `har_to_contract.py` 扩 v2 → `contract_har.json` | §2 观测层、R1/R2 |
| 4 | `scripts/merge_contracts.py` → `contract_final.json`（薄封装 `merge_contracts()`） | §4 全部、§5 |
| 5 | `scripts/verify_p3_baseline.py`（召回率/元数据覆盖率/多源重合度/隐藏接口） | §5 status、`contradictions` |

