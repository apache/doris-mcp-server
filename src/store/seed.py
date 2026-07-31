"""Seed data: example database tables + semantic models.

On first startup, this module creates:
  - dw.orders, dw.users, dw.products, dw.dim_date tables with sample data
  - example semantic model YAML files in active_store_example

Connections delegate to store.store._get_conn() which reads request-scoped
credentials via contextvar.  Idempotent: checks if tables/files already
exist before creating.
"""

from __future__ import annotations

import logging
from datetime import datetime

from store.store import _get_conn, set_doris_port as _store_set_port

logger = logging.getLogger("doris_new_mcp.seed")

EXAMPLE_MODEL_FILENAMES = frozenset({
    "orders.yaml",
    "users.yaml",
    "products.yaml",
    "project.yaml",
})
EXAMPLE_DATA_TABLES = frozenset({
    "orders",
    "users",
    "products",
    "dim_date",
})


def set_doris_port(port: int) -> None:
    _store_set_port(port)

# ---------------------------------------------------------------------------
# Sample table DDL
# ---------------------------------------------------------------------------

_ORDERS_DDL = """\
CREATE TABLE IF NOT EXISTS dw.orders (
    order_id    BIGINT,
    user_id     BIGINT,
    product_id  BIGINT,
    amount      DECIMAL(10,2),
    channel     VARCHAR(32),
    status      VARCHAR(32),
    order_date  DATE
)
UNIQUE KEY(order_id)
DISTRIBUTED BY HASH(order_id) BUCKETS 4
PROPERTIES ('replication_num' = '1')
"""

_USERS_DDL = """\
CREATE TABLE IF NOT EXISTS dw.users (
    user_id       BIGINT,
    name          VARCHAR(64),
    city          VARCHAR(64),
    level         VARCHAR(32),
    register_date DATE
)
UNIQUE KEY(user_id)
DISTRIBUTED BY HASH(user_id) BUCKETS 4
PROPERTIES ('replication_num' = '1')
"""

_PRODUCTS_DDL = """\
CREATE TABLE IF NOT EXISTS dw.products (
    product_id  BIGINT,
    name        VARCHAR(128),
    category    VARCHAR(64),
    brand       VARCHAR(64),
    price       DECIMAL(10,2)
)
UNIQUE KEY(product_id)
DISTRIBUTED BY HASH(product_id) BUCKETS 4
PROPERTIES ('replication_num' = '1')
"""

_DIM_DATE_DDL = """\
CREATE TABLE IF NOT EXISTS dw.dim_date (
    date_id    DATE,
    year       INT,
    month      INT,
    day        INT,
    day_of_week VARCHAR(32)
)
UNIQUE KEY(date_id)
DISTRIBUTED BY HASH(date_id) BUCKETS 4
PROPERTIES ('replication_num' = '1')
"""

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_ORDERS_DATA = [
    (1, 1, 1, 199.00, "WEB",  "completed", "2026-01-15"),
    (2, 2, 2, 599.00, "APP",  "completed", "2026-01-16"),
    (3, 3, 3, 299.00, "WEB",  "completed", "2026-01-17"),
    (4, 1, 4, 199.00, "APP",  "cancelled", "2026-01-18"),
    (5, 4, 5, 899.00, "WEB",  "completed", "2026-01-19"),
    (6, 2, 3, 599.00, "APP",  "completed", "2026-02-10"),
    (7, 5, 1, 149.00, "MINI", "completed", "2026-02-12"),
    (8, 3, 4, 199.00, "WEB",  "completed", "2026-02-14"),
    (9, 1, 2, 299.00, "APP",  "cancelled", "2026-02-20"),
    (10, 4, 5, 899.00, "APP", "completed", "2026-03-01"),
    (11, 3, 2, 599.00, "WEB", "completed", "2026-03-05"),
    (12, 5, 3, 149.00, "MINI","completed", "2026-03-10"),
]

_USERS_DATA = [
    (1, "张三", "北京", "VIP",    "2025-06-01"),
    (2, "李四", "上海", "普通",  "2025-08-15"),
    (3, "王五", "深圳", "VIP",    "2025-10-01"),
    (4, "赵六", "杭州", "普通",  "2026-01-10"),
    (5, "孙七", "广州", "普通",  "2026-02-01"),
]

_PRODUCTS_DATA = [
    (1, "无线耳机",   "电子", "索尼",   199.00),
    (2, "机械键盘",   "电子", "罗技",   599.00),
    (3, "运动鞋",     "服装", "耐克",   299.00),
    (4, "背包",       "配饰", "新秀丽", 199.00),
    (5, "智能手表",   "电子", "华为",   899.00),
]

# ---------------------------------------------------------------------------
# Example semantic model YAML
# ---------------------------------------------------------------------------

_ORDERS_YAML = """---
semantic_model:
  name: orders
  description: 订单表
  label: 订单表

  db_table: dw.orders

  defaults:
    agg_time_dimension: order_date

  entities:
    - name: order
      type: primary
      expr: order_id
      label: 订单
    - name: user
      type: foreign
      expr: user_id
      label: 用户

  measures:
    - name: total_amount
      expr: amount
      agg: sum
      description: 订单总金额
    - name: order_count
      expr: order_id
      agg: count_distinct
      description: 订单数
    - name: avg_amount
      expr: amount
      agg: average
      description: 平均客单价
    - name: unique_users
      expr: user_id
      agg: count_distinct
      description: 下单用户数

  dimensions:
    - name: order_date
      type: time
      type_params:
        time_granularity: day
      expr: order_date
      label: 下单日期
    - name: channel
      type: categorical
      label: 渠道
    - name: status
      type: categorical
      label: 状态
"""

_USERS_YAML = """---
semantic_model:
  name: users
  description: 用户表
  label: 用户表

  db_table: dw.users

  defaults:
    agg_time_dimension: register_date

  entities:
    - name: user
      type: primary
      expr: user_id
      label: 用户

  measures:
    - name: user_count
      expr: user_id
      agg: count_distinct
      description: 用户数

  dimensions:
    - name: city
      type: categorical
      label: 城市
    - name: level
      type: categorical
      label: 等级
    - name: register_date
      type: time
      type_params:
        time_granularity: day
      expr: register_date
      label: 注册日期
"""

_PRODUCTS_YAML = """---
semantic_model:
  name: products
  description: 商品表
  label: 商品表

  db_table: dw.products

  entities:
    - name: product
      type: primary
      expr: product_id
      label: 商品

  measures:
    - name: product_count
      expr: product_id
      agg: count_distinct
      description: 商品数
      create_metric: false

  dimensions:
    - name: category
      type: categorical
      label: 分类
    - name: brand
      type: categorical
      label: 品牌
"""

_PROJECT_YAML = """---
time_config:
  calendar:
    - table: dw.dim_date
      column: date_id
      grain: day
"""


# ---------------------------------------------------------------------------
# Seed functions
# ---------------------------------------------------------------------------

def seed_example_data() -> bool:
    """Create example database tables with sample data. Idempotent.
    
    Returns True if any seeding was performed, False if already exists.
    """
    performed = False
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            # Create database if needed
            cur.execute("CREATE DATABASE IF NOT EXISTS dw")

            # Create tables
            for name, ddl in [
                ("dw.orders", _ORDERS_DDL),
                ("dw.users", _USERS_DDL),
                ("dw.products", _PRODUCTS_DDL),
                ("dw.dim_date", _DIM_DATE_DDL),
            ]:
                cur.execute(ddl)

            # Insert sample data if tables are empty
            for table, data in [
                ("dw.orders", _ORDERS_DATA),
                ("dw.users", _USERS_DATA),
                ("dw.products", _PRODUCTS_DATA),
            ]:
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                row = cur.fetchone()
                cnt = row[0] if row else 0
                if cnt == 0:
                    columns = {
                        "dw.orders": "order_id, user_id, product_id, amount, channel, status, order_date",
                        "dw.users": "user_id, name, city, level, register_date",
                        "dw.products": "product_id, name, category, brand, price",
                    }[table]
                    placeholders = ", ".join(["(%s, %s, %s, %s, %s, %s, %s)"] * len(data)) if table == "dw.orders" \
                        else ", ".join(["(%s, %s, %s, %s, %s)"] * len(data))
                    flat: list = []
                    for row in data:
                        flat.extend(row)
                    cur.execute(
                        f"INSERT INTO {table} ({columns}) VALUES {placeholders}",
                        flat,
                    )
                    performed = True
                    logger.info(f"Seeded {len(data)} rows into {table}")

            # Seed dim_date
            cur.execute("SELECT COUNT(*) FROM dw.dim_date")
            row = cur.fetchone()
            if row and row[0] == 0:
                from datetime import date as _date, timedelta as _timedelta
                for i in range(365):
                    d = _date(2026, 1, 1) + _timedelta(days=i)
                    cur.execute(
                        "INSERT INTO dw.dim_date VALUES (%s, %s, %s, %s, %s)",
                        (d.strftime("%Y-%m-%d"), d.year, d.month, d.day, d.strftime("%A")),
                    )
                performed = True
                logger.info("Seeded 365 rows into dw.dim_date")

    finally:
        conn.close()
    return performed


def seed_example_models() -> bool:
    """Upsert example semantic model files into active_store_example.
    Idempotent: inserts only missing built-in files and preserves existing files.
    
    Returns True if seeding was performed, False if already exists.
    """
    conn = _get_conn()
    now = datetime.now()
    performed = False
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE DATABASE IF NOT EXISTS system_mcp")
            cur.execute("USE system_mcp")

            # Ensure table exists
            cur.execute("""\
                CREATE TABLE IF NOT EXISTS active_store_example (
                    filename    VARCHAR(512) NOT NULL,
                    updated_at  DATETIME NOT NULL,
                    content     STRING NOT NULL
                ) UNIQUE KEY(filename)
                DISTRIBUTED BY HASH(filename) BUCKETS 1
                PROPERTIES ('replication_num' = '1')
            """)

            cur.execute("SELECT filename FROM active_store_example")
            existing = {row[0] for row in cur.fetchall()}

            models = [
                ("orders.yaml",    _ORDERS_YAML),
                ("users.yaml",     _USERS_YAML),
                ("products.yaml",  _PRODUCTS_YAML),
                ("project.yaml",   _PROJECT_YAML),
            ]
            for filename, content in models:
                if filename in existing:
                    continue
                cur.execute(
                    "INSERT INTO active_store_example (filename, updated_at, content) VALUES (%s, %s, %s)",
                    (filename, now, content.strip()),
                )
                performed = True
            if performed:
                logger.info("Seeded missing example models into active_store_example")

    finally:
        conn.close()
    return performed


def is_example_deployed() -> bool:
    """Return whether all built-in example models and data tables exist."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            try:
                cur.execute("SHOW TABLES FROM system_mcp LIKE 'active_store_example'")
                if not cur.fetchone():
                    return False
                cur.execute("SELECT filename FROM system_mcp.active_store_example")
                model_files = {row[0] for row in cur.fetchall()}
                if not EXAMPLE_MODEL_FILENAMES.issubset(model_files):
                    return False

                cur.execute("SHOW TABLES FROM dw")
                data_tables = {row[0] for row in cur.fetchall()}
                return EXAMPLE_DATA_TABLES.issubset(data_tables)
            except Exception:
                return False
    finally:
        conn.close()


def delete_example() -> None:
    """Delete the built-in example semantic files and sample data tables."""
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS system_mcp.staging_store_example")
            cur.execute("DROP TABLE IF EXISTS system_mcp.active_store_example")
            for table in sorted(EXAMPLE_DATA_TABLES):
                cur.execute(f"DROP TABLE IF EXISTS dw.{table}")
    finally:
        conn.close()
    logger.info("Deleted example semantic files and sample data tables")


def seed_all() -> bool:
    """Run all seeding. Returns True if anything was seeded."""
    d = seed_example_data()
    m = seed_example_models()
    return d or m
