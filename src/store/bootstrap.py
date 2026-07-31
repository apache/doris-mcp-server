"""Bootstrap semantic manifest from user YAML config files.

Uses the built-in MetricFlow YAML parser to directly compile semantic models
without requiring dbt or a live Doris connection.

User provides:
  config/models/*.yml

Supports both MetricFlow's native `node_relation` format and a simplified
`db_table` shorthand:

  node_relation:                  db_table: dw.fact_orders
    schema_name: dw          ≡
    alias: fact_orders

Output:
  workspace/target/semantic_manifest.json  — compiled manifest for MetricFlow engine
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import tempfile
from pathlib import Path

import yaml

from metricflow.semantic_interfaces.parsing.dir_to_model import (
    parse_directory_of_yaml_files_to_semantic_manifest,
)

logger = logging.getLogger("doris_new_mcp.semantic")

_DB_TABLE_RE = re.compile(r'^(\s*)db_table:\s*(.+)$', re.MULTILINE)


def _normalize_db_table(yaml_text: str) -> tuple[str, bool]:
    """Convert `db_table: dw.fact_orders` into MetricFlow-native `node_relation:` format.

    Supports:
      db_table: dw.fact_orders          → schema_name: dw, alias: fact_orders
      db_table: analytics.dw.fact_orders → database: analytics, schema_name: dw, alias: fact_orders

    Returns (transformed_yaml, was_modified).
    """
    match = _DB_TABLE_RE.search(yaml_text)
    if not match:
        return yaml_text, False

    indent = match.group(1)  # preserve original indentation
    inner = indent + "  "
    table_ref = match.group(2).strip().strip('"').strip("'")
    parts = table_ref.split(".")

    if len(parts) == 2:
        schema_name, alias = parts
        node_yaml = f"{indent}node_relation:\n{inner}schema_name: {schema_name}\n{inner}alias: {alias}"
    elif len(parts) == 3:
        database, schema_name, alias = parts
        node_yaml = f"{indent}node_relation:\n{inner}database: {database}\n{inner}schema_name: {schema_name}\n{inner}alias: {alias}"
    else:
        logger.warning(f"Invalid db_table value: {table_ref}, expected 2 or 3 dot-separated parts")
        return yaml_text, False

    transformed = _DB_TABLE_RE.sub(node_yaml, yaml_text)
    logger.info(f"Normalized db_table='{table_ref}' → node_relation")
    return transformed, True


def _ensure_create_metric_default(yaml_text: str) -> tuple[str, bool]:
    """Auto-add `create_metric: true` to measures that don't explicitly set it.

    Parses the YAML, walks semantic_model.measures, and sets create_metric=True
    on any measure that doesn't already have the field. Preserves all other content.
    """
    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError:
        return yaml_text, False

    modified = False
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        sm = doc.get("semantic_model")
        if not isinstance(sm, dict):
            continue
        measures = sm.get("measures")
        if not isinstance(measures, list):
            continue
        for m in measures:
            if isinstance(m, dict) and "create_metric" not in m:
                m["create_metric"] = True
                modified = True

    if not modified:
        return yaml_text, False

    # Serialize back to YAML, preserving document separators
    parts = []
    for i, doc in enumerate(docs):
        if i > 0:
            parts.append("---")
        parts.append(yaml.dump(doc, default_flow_style=False, allow_unicode=True, sort_keys=False))
    transformed = "\n".join(parts)
    logger.info("Auto-added create_metric: true to measures without explicit setting")
    return transformed, True


def _normalize_time_config(yaml_text: str) -> tuple[str, bool]:
    """Convert `time_config:` shorthand into MetricFlow-native `project_configuration:`.

    Simplified format:
      time_config:
        calendar:
          - table: analytics.date_dim
            column: dt
            grain: day

    Gets converted to:
      project_configuration:
        time_spines:
          - node_relation:
              alias: date_dim
              schema_name: analytics
            primary_column:
              name: dt
              time_granularity: day

    Supports multi-part table: table: catalog.analytics.date_dim
    Supports multiple calendars and grains: day, week, month, quarter, year, hour, minute, second
    """
    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError:
        return yaml_text, False

    modified = False
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        tc = doc.pop("time_config", None)
        if not isinstance(tc, dict):
            continue

        calendars = tc.get("calendar")
        if not isinstance(calendars, list) or not calendars:
            continue

        time_spines = []
        for cal in calendars:
            if not isinstance(cal, dict):
                continue
            table_ref = cal.get("table", "")
            column = cal.get("column", "ds")
            grain = cal.get("grain", "day")

            parts = table_ref.split(".")
            if len(parts) == 2:
                node_relation = {"alias": parts[1], "schema_name": parts[0]}
            elif len(parts) == 3:
                node_relation = {"alias": parts[2], "schema_name": parts[1], "database": parts[0]}
            else:
                logger.warning(f"Invalid calendar table '{table_ref}', skipping")
                continue

            time_spines.append({
                "node_relation": node_relation,
                "primary_column": {"name": column, "time_granularity": grain},
            })

        if time_spines:
            doc["project_configuration"] = {"time_spines": time_spines}
            modified = True

    if not modified:
        return yaml_text, False

    parts = []
    for i, doc in enumerate(docs):
        if i > 0:
            parts.append("---")
        parts.append(yaml.dump(doc, default_flow_style=False, allow_unicode=True, sort_keys=False))
    transformed = "\n".join(parts)
    logger.info("Normalized time_config → project_configuration")
    return transformed, True


def _copy_and_normalize_models(source_dir: Path, temp_dir: Path) -> bool:
    """Copy all YAML files to temp_dir, transforming db_table → node_relation
    and auto-adding create_metric: true to measures.

    Returns True if any file was modified.
    """
    any_modified = False
    for yaml_file in source_dir.rglob("*.yml"):
        rel = yaml_file.relative_to(source_dir)
        dest = temp_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)

        text = yaml_file.read_text(encoding="utf-8")
        text, m1 = _normalize_time_config(text)
        text, m2 = _normalize_db_table(text)
        text, m3 = _ensure_create_metric_default(text)
        dest.write_text(text, encoding="utf-8")

        if m1 or m2 or m3:
            any_modified = True

    for yaml_file in source_dir.rglob("*.yaml"):
        rel = yaml_file.relative_to(source_dir)
        dest = temp_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)

        text = yaml_file.read_text(encoding="utf-8")
        text, m1 = _normalize_time_config(text)
        text, m2 = _normalize_db_table(text)
        text, m3 = _ensure_create_metric_default(text)
        dest.write_text(text, encoding="utf-8")

        if m1 or m2 or m3:
            any_modified = True

    return any_modified


def bootstrap_from_yaml(models_dir: Path, workspace_dir: Path) -> tuple[bool, str]:
    """Parse YAML model files directly into a semantic manifest.

    No dbt, no Doris connection, no dbt_project.yml or profiles.yml needed.
    Pure in-process YAML → PydanticSemanticManifest → JSON.

    Supports `db_table: db.table` as a shorthand for `node_relation:`.

    Args:
        models_dir: Directory containing semantic model and metric YAML files
        workspace_dir: Workspace directory where target/semantic_manifest.json will be written

    Returns:
        (success, error_message)
    """
    if not models_dir.exists():
        return False, f"models/ directory not found: {models_dir}"

    logger.info(f"Bootstrapping from YAML: models={models_dir}")

    # Pre-process: convert db_table → node_relation in a temp directory
    temp_dir = Path(tempfile.mkdtemp(prefix="mf_models_"))
    parse_dir = str(models_dir)
    try:
        modified = _copy_and_normalize_models(models_dir, temp_dir)
        if modified:
            parse_dir = str(temp_dir)
            logger.info(f"Using normalized models in: {temp_dir}")
    except Exception as e:
        logger.warning(f"db_table normalization failed ({e}), using original files")

    try:
        result = parse_directory_of_yaml_files_to_semantic_manifest(
            directory=parse_dir,
            apply_transformations=True,
            raise_issues_as_exceptions=False,
        )
    except Exception as e:
        logger.error(f"YAML parsing failed: {e}")
        return False, f"YAML parsing failed: {e}"
    finally:
        shutil.rmtree(str(temp_dir), ignore_errors=True)

    if result.issues.has_blocking_issues:
        issue_msgs = [str(i) for i in result.issues.all_issues]
        msg = "; ".join(issue_msgs[:5])  # first 5 issues
        logger.error(f"Validation issues: {msg}")
        return False, f"Validation failed: {msg}"

    manifest = result.semantic_manifest
    if manifest is None:
        return False, "YAML parsing produced no manifest"

    # Write the compiled manifest to target/
    target_dir = workspace_dir / "target"
    target_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = target_dir / "semantic_manifest.json"

    try:
        manifest_json = manifest.json(indent=2)
        manifest_path.write_text(manifest_json)
        logger.info(f"Semantic manifest written to {manifest_path}")
        return True, ""
    except Exception as e:
        return False, f"Failed to write manifest: {e}"


def bootstrap(config_dir: Path, workspace_dir: Path, models_dir: Path | None = None) -> tuple[bool, str]:
    """Full bootstrap: parse YAML models directly into semantic_manifest.json.

    Args:
        config_dir: Config directory (used only for default models_dir resolution)
        workspace_dir: Workspace directory
        models_dir: Override for user models directory. Defaults to config_dir/models.

    Returns:
        (success, error_message)
    """
    effective_models = models_dir or (config_dir / "models")
    return bootstrap_from_yaml(effective_models, workspace_dir)


def pre_validate_physical(
    models_dir: Path,
    db_host: str | None = None,
    db_port: int | None = None,
    db_user: str | None = None,
    db_password: str | None = None,
) -> tuple[bool, str]:
    """Validate that all tables and columns referenced in model YAML files
    actually exist in Doris.

    Checks for each semantic_model:
      - db_table / node_relation resolves to an existing Doris table
      - entity.expr column exists (only for simple column names, not SQL expressions)
      - measure.expr column exists (only for simple column names, not SQL expressions)
      - dimension.expr column exists (only for simple column names, not SQL expressions)
      - time_config / project_configuration calendar table exists

    Args:
        models_dir: Directory containing YAML model files
        db_host: Doris host (defaults to store's _DORIS_HOST)
        db_port: Doris port (defaults to store's _DORIS_PORT)
        db_user: Doris user (overrides request credentials)
        db_password: Doris password (overrides request credentials)

    Returns:
        (success, error_message)
    """
    import pymysql as _pymysql
    import yaml
    import re as _re

    if not models_dir.exists():
        return False, f"Models directory not found: {models_dir}"

    # P2-4: Resolve connection config — prefer explicit params, then request
    # contextvar credentials (set by server.py before all store operations).
    from store.store import _DORIS_HOST, _DORIS_PORT, _request_creds
    host = db_host or _DORIS_HOST
    port = db_port or _DORIS_PORT
    if db_user and db_password is not None:
        user, password = db_user, db_password
    else:
        creds = _request_creds.get()
        if creds is None:
            return False, "No Doris credentials available — request must carry a valid Bearer token"
        user, password = creds

    # P1-3: Detect expressions that are NOT simple column names
    # Simple column name: starts with letter, contains only [a-zA-Z0-9_], no spaces/parens/commas
    _SIMPLE_COLUMN_RE = _re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')

    def _is_sql_expression(expr: str) -> bool:
        """Return True if expr looks like a SQL expression rather than a simple column."""
        return not _SIMPLE_COLUMN_RE.match(expr)

    # Collect all table/column references
    references: list[tuple[str, str, str, str]] = []  # (model, ref_type, table, col)
    table_set: set[str] = set()

    for yaml_file in sorted(list(models_dir.rglob("*.yml")) + list(models_dir.rglob("*.yaml"))):
        try:
            text = yaml_file.read_text(encoding="utf-8")
            docs = list(yaml.safe_load_all(text))
        except Exception as e:
            return False, f"Failed to parse {yaml_file.name}: {e}"

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            sm = doc.get("semantic_model")
            if not isinstance(sm, dict):
                continue
            
            model_name = sm.get("name", yaml_file.stem)
            table = _resolve_table_ref(sm)
            if not table:
                return False, f"[{model_name}] No db_table or node_relation defined"
            table_set.add(table)

            for ent in sm.get("entities", []) or []:
                expr = ent.get("expr")
                if expr and not _is_sql_expression(expr):
                    references.append((model_name, "entity", table, expr))

            for m in sm.get("measures", []) or []:
                expr = m.get("expr")
                if expr and not _is_sql_expression(expr):
                    references.append((model_name, "measure", table, expr))

            for dim in sm.get("dimensions", []) or []:
                expr = dim.get("expr")
                if expr and not _is_sql_expression(expr):
                    references.append((model_name, "dimension", table, expr))

        # P1-4: Collect calendar/time-spine tables from time_config or project_configuration
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            # time_config shorthand
            tc = doc.get("time_config")
            if isinstance(tc, dict):
                calendars = tc.get("calendar", [])
                if isinstance(calendars, list):
                    for cal in calendars:
                        if isinstance(cal, dict) and cal.get("table"):
                            table_set.add(cal["table"])
            # project_configuration native format
            pc = doc.get("project_configuration")
            if isinstance(pc, dict):
                spines = pc.get("time_spines", [])
                if isinstance(spines, list):
                    for spine in spines:
                        if isinstance(spine, dict):
                            nr = spine.get("node_relation", {})
                            if isinstance(nr, dict):
                                parts = []
                                if nr.get("database"):
                                    parts.append(nr["database"])
                                schema = nr.get("schema_name") or nr.get("schema")
                                if schema:
                                    parts.append(schema)
                                alias = nr.get("alias")
                                if alias:
                                    parts.append(alias)
                                if parts:
                                    table_set.add(".".join(parts))

    # Verify tables and columns via pymysql
    conn = _pymysql.connect(host=host, port=port, user=user, password=password, charset="utf8mb4")
    try:
        table_columns: dict[str, set[str]] = {}
        with conn.cursor() as cur:
            for table in sorted(table_set):
                try:
                    cur.execute(f"DESCRIBE {table}")
                    rows = cur.fetchall()
                    if not rows:
                        conn.close()
                        return False, f"Table {table} does not exist or is empty"
                    table_columns[table] = {row[0] for row in rows}
                except Exception as e:
                    conn.close()
                    return False, f"Table {table}: {e}"

            for model, ref_type, table, col in references:
                if col not in table_columns.get(table, set()):
                    conn.close()
                    return False, f"[{model}] {ref_type} references missing column: {table}.{col}"
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return True, ""


def _resolve_table_ref(sm: dict) -> str | None:
    """Extract fully-qualified table name from semantic_model dict."""
    db_table = sm.get("db_table")
    if db_table and isinstance(db_table, str):
        return db_table

    nr = sm.get("node_relation")
    if isinstance(nr, dict):
        parts = []
        if nr.get("database"):
            parts.append(nr["database"])
        schema = nr.get("schema_name") or nr.get("schema")
        if schema:
            parts.append(schema)
        alias = nr.get("alias")
        if alias:
            parts.append(alias)
        if parts:
            return ".".join(parts)

    return None