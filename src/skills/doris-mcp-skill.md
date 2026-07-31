# Doris MCP Query Skill

> You are reading this because you called `get_query_guide()`. All tool-calling rules below are mandatory — follow them strictly.

## tl;dr — The Six Essential Tools

```
get_query_guide()                        → you are here (already called)
check_service_health()                   → which workspace is healthy?
list_metrics(workspace)                  → what can I ask?
list_dimensions_for_metric(workspace, name) → how can I slice it?
query_metric(workspace, metrics, ...)    → give me the data
execute_query(sql, ...)                  → raw SQL, last resort only
```

`workspace` is required for the first three. Use `"example"` for the built-in sample.

---

## Step 0: Check Health (ALWAYS SECOND — get_query_guide was already called)

Call this immediately after receiving this guide:

```
check_service_health()
```

Returns:

```json
{
  "doris": "connected",
  "workspaces": {
    "example":   {"status": "healthy",    "metric_count": 5},
    "marketing": {"status": "no_models",  "message": "No YAML files"},
    "finance":   {"status": "not_ready",  "message": "Files present but failed to load"}
  }
}
```

**Rules:**
- Pick a workspace with `status: "healthy"` — only `query_metric` works there.
- If the user mentions a specific workspace, use it. Otherwise use `"example"`.
- If `doris` is `"unavailable"`, warn the user. `list_databases` / `execute_query` may still work.
- If NO workspace is healthy → fall back to raw SQL path (see bottom).

---

## Step 1: list_metrics — What Can I Ask?

```json
// Request
{"workspace": "example"}

// Response
{
  "data": [
    {"name": "total_amount", "description": "订单总金额"},
    {"name": "order_count",   "description": "订单数"},
    {"name": "avg_amount",    "description": "平均客单价"},
    {"name": "unique_users",  "description": "下单用户数"},
    {"name": "user_count",    "description": "用户数"}
  ],
  "meta": {"total_count": 5}
}
```

**How to match user intent to a metric:**
- "销售额 / 营收 / GMV" → `total_amount`
- "订单量 / 成交量" → `order_count`
- "客单价" → `avg_amount`
- "下单用户数" → `unique_users`
- "用户数" → `user_count`

If the user's question doesn't clearly match any metric, call `list_metrics` and scan all descriptions. If nothing matches, fall back to raw SQL.

---

## Step 2: list_dimensions_for_metric — How Can I Slice It?

```json
// Request
{"workspace": "example", "metric_name": "total_amount"}

// Response
{
  "data": [
    {"name": "order_date",    "type": "time",        "description": "下单日期（按天）"},
    {"name": "channel",       "type": "categorical", "description": "下单渠道"},
    {"name": "status",        "type": "categorical", "description": "订单状态"},
    {"name": "city",          "type": "categorical", "description": "城市"},
    {"name": "level",         "type": "categorical", "description": "等级"},
    {"name": "register_date", "type": "time",        "description": "注册日期"},
    {"name": "category",      "type": "categorical", "description": "分类"},
    {"name": "brand",         "type": "categorical", "description": "品牌"}
  ],
  "meta": {"metric": "total_amount", "count": 8}
}
```

**Rules:**
- `type: "time"` → can group by day/week/month/quarter/year. Use `"month"` in `group_by`.
- `type: "categorical"` → discrete buckets. Use `"channel"`, `"city"`, etc.
- The engine auto-joins across tables. `city` comes from `users`, but works with `total_amount` from `orders` — no JOIN needed.
- Always check dimensions BEFORE calling `query_metric`. Using a dimension not in this list causes errors.

---

## Step 3: query_metric — Give Me the Data

### Parameters

| Param | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `workspace` | string | **Yes** | — | `"example"` |
| `metrics` | list[string] | **Yes** | — | e.g. `["total_amount", "order_count"]` |
| `group_by` | list[string] | No | `[]` | Dimension names from Step 2. Time grains: `"day"`, `"week"`, `"month"`, `"quarter"`, `"year"` |
| `where` | string | No | `""` | SQL predicate or JSON object |
| `order_by` | list[string] | No | `[]` | `-` prefix = DESC, e.g. `["-total_amount"]` |
| `limit` | int | No | `0` | Max rows. `0` = no limit |
| `having` | string | No | `""` | Filter on aggregated value, e.g. `"total_amount > 1000"` |
| `database` | string | No | `""` | Target Doris database (auto-detected if empty) |
| `max_rows` | int | No | `0` | Hard row cap for execution. `0` = server default (10,000) |

### Response

```json
{
  "data": {
    "columns": ["channel", "total_amount"],
    "rows": [
      {"channel": "APP",  "total_amount": 2396.00},
      {"channel": "WEB",  "total_amount": 2096.00},
      {"channel": "MINI", "total_amount": 298.00}
    ]
  },
  "meta": {"duration_ms": 12.5, "row_count": 3}
}
```

### WHERE Syntax

All forms are auto-normalized — pick whichever is easiest:

```python
# Plain SQL
where="channel = 'APP'"
where="order_date >= '2026-02-01' AND order_date <= '2026-02-28'"
where="channel IN ('APP', 'MINI')"

# JSON object (AND-joined)
where='{"channel": "APP", "status": "completed"}'

# JSON with array values (IN clause)
where='{"channel": ["APP", "MINI"]}'
```

### HAVING Syntax

Filter on the **aggregated result**. References metric names from the output columns:

```python
# Single condition
having="total_amount > 1000"

# Multiple conditions
having="total_amount > 500 AND order_count > 2"
```

**Do NOT** pass Jinja templates, JSON objects, or double-quoted strings in `having`. Plain SQL comparisons only.

### Ordering

```python
order_by=["-total_amount"]   # DESC
order_by=["channel"]          # ASC
order_by=["-total_amount", "channel"]  # multi-column
```

### Full Examples

```json
// "各渠道销售额"
{"workspace": "example", "metrics": ["total_amount"], "group_by": ["channel"]}

// "2月份每日订单量趋势"
{"workspace": "example", "metrics": ["order_count"], "group_by": ["order_date"],
 "where": "order_date >= '2026-02-01' AND order_date <= '2026-02-28'",
 "order_by": ["order_date"]}

// "销售额 Top 3 渠道"
{"workspace": "example", "metrics": ["total_amount"], "group_by": ["channel"],
 "order_by": ["-total_amount"], "limit": 3}

// "已完成订单的渠道分布"
{"workspace": "example", "metrics": ["total_amount", "order_count"],
 "group_by": ["channel"], "where": "status = 'completed'"}

// "各品牌销售额，只看卖得好的"
{"workspace": "example", "metrics": ["total_amount"], "group_by": ["brand"],
 "order_by": ["-total_amount"], "having": "total_amount > 500"}
```

---

## When to Use Raw SQL (execute_query)

**Only two scenarios justify `execute_query`:**

### Scenario A — Semantic Layer Unavailable
`check_service_health` returns NO workspace with `status: "healthy"`.

### Scenario B — No Matching Metric
Semantic layer IS healthy, but `list_metrics` shows nothing matching the user's intent.

**CRITICAL RULE — NEVER skip the semantic layer when it can serve the query:**
- If `check_service_health` shows at least one `healthy` workspace AND `list_metrics` has a matching metric → you MUST use `query_metric`. Do NOT write raw SQL.
- Only fall back to `execute_query` when the semantic layer truly cannot help (Scenario A or B above).

**In either case, follow this fallback path:**

### Fallback: Raw SQL

```
list_databases()                              → find database
list_tables(database="dw")                    → find tables
describe_table(database="dw", table="orders") → check columns
execute_query(sql="SELECT ... FROM dw.orders ...")
```

**ALWAYS warn the user before using raw SQL:**

> "No semantic metrics match your query. Results below come from raw SQL and may have incorrect aggregation or duplicate counting. Use with caution."

---

## Common Mistakes

| ❌ Don't | ✅ Do |
|----------|------|
| Skip `get_query_guide` or `check_service_health` | Always call them first — they tell you which workspace to use |
| Forget `workspace` parameter | Every semantic tool requires it |
| Use raw SQL when metrics exist | `list_metrics` → `query_metric` is always preferred |
| Call `query_metric` before checking dimensions | `list_dimensions_for_metric` first to verify `group_by` values |
| Write `having='{"x": 10}'` (JSON) | `having` takes plain SQL: `"x > 10"` |
| Use `describe_table` to plan metric queries | Use `list_metrics` — metrics handle joins automatically |
| Report raw SQL results as authoritative | Always add the warning |
