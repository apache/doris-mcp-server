"""Cross-file dependency detection for safe YAML deletion.

Called BEFORE staging a file for deletion — checks whether any surviving
active file references measures, models, or entities exported by the
file being deleted.
"""

from __future__ import annotations


def check_delete_dependencies(
    deleted_filename: str,
    deleted_content: str,
    active_files: dict[str, str],
) -> list[str]:
    """Check whether deleting *deleted_filename* would break any surviving file.

    Args:
        deleted_filename: The file being deleted (e.g. ``"orders.yaml"``).
        deleted_content: The YAML content of the file being deleted.
        active_files: Dict of ``{filename: content}`` for ALL active files
                      (INCLUDING the deleted file, for simplicity).

    Returns:
        A list of error strings, one per broken reference.  Empty list
        means the deletion is safe.
    """
    exports = _extract_exports(deleted_content)

    if not exports["measures"] and not exports["models"] and not exports["entities"]:
        return []

    errors: list[str] = []
    for fname, content in active_files.items():
        if fname == deleted_filename:
            continue
        if not fname.endswith((".yml", ".yaml")):
            continue

        refs = _extract_references(content)

        for m in exports["measures"]:
            if m in refs["measures"]:
                if not _measure_provided_by(m, fname, active_files, deleted_filename):
                    errors.append(
                        f"Cannot delete '{deleted_filename}': "
                        f"'{fname}' references measure '{m}' defined in '{deleted_filename}'"
                    )

        for mdl in exports["models"]:
            if mdl in refs["models"]:
                if not _model_provided_by(mdl, fname, active_files, deleted_filename):
                    errors.append(
                        f"Cannot delete '{deleted_filename}': "
                        f"'{fname}' references model '{mdl}' defined in '{deleted_filename}'"
                    )

        for ent in exports["entities"]:
            if ent in refs["entities"]:
                if not _entity_provided_by(ent, fname, active_files, deleted_filename):
                    errors.append(
                        f"Cannot delete '{deleted_filename}': "
                        f"'{fname}' references entity '{ent}' defined in '{deleted_filename}'"
                    )

    return errors


# ---------------------------------------------------------------------------
# Helpers: export extraction
# ---------------------------------------------------------------------------

def _extract_exports(yaml_content: str) -> dict[str, list[str]]:
    """Extract ``{measures, models, entities}`` that a file exports.

    Measures with ``create_metric: false`` are excluded.
    """
    import yaml

    measures: list[str] = []
    models: list[str] = []
    entities: list[str] = []

    try:
        docs = list(yaml.safe_load_all(yaml_content))
    except Exception:
        return {"measures": measures, "models": models, "entities": entities}

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        sm = doc.get("semantic_model")
        if not isinstance(sm, dict):
            continue

        model_name = sm.get("name", "")
        if model_name:
            models.append(model_name)

        for m in sm.get("measures") or []:
            if not isinstance(m, dict):
                continue
            if m.get("create_metric", True) is not False:
                mname = m.get("name", "")
                if mname:
                    measures.append(mname)

        for e in sm.get("entities") or []:
            if not isinstance(e, dict):
                continue
            ename = e.get("name", "")
            if ename:
                entities.append(ename)

    return {"measures": measures, "models": models, "entities": entities}


# ---------------------------------------------------------------------------
# Helpers: reference extraction
# ---------------------------------------------------------------------------

def _extract_references(yaml_content: str) -> dict[str, list[str]]:
    """Extract ``{measures, models, entities}`` that a file references.

    Detects references from:
    - derived metrics (``expr`` field)
    - ratio metrics (``numerator``, ``denominator``)
    - conversion metrics (``entity``)
    - foreign entities (``type: foreign``)
    - dbt-style model references (``model: ref('name')`` or plain name)
    """
    import yaml

    measures: set[str] = set()
    models: set[str] = set()
    entities: set[str] = set()

    try:
        docs = list(yaml.safe_load_all(yaml_content))
    except Exception:
        return {"measures": list(measures), "models": list(models), "entities": list(entities)}

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        sm = doc.get("semantic_model")
        if not isinstance(sm, dict):
            continue

        model_ref = sm.get("model", "")
        if isinstance(model_ref, str) and model_ref.strip():
            models.add(_extract_ref_name(model_ref))

        for e in sm.get("entities") or []:
            if isinstance(e, dict) and e.get("type") == "foreign":
                ename = e.get("name", "")
                if ename:
                    entities.add(ename)

        for metric in sm.get("metrics") or []:
            if not isinstance(metric, dict):
                continue
            mtype = metric.get("type", "")

            if mtype == "derived":
                expr = metric.get("expr", "")
                names = _extract_measure_names_from_expr(expr)
                measures.update(names)

            elif mtype == "ratio":
                for key in ("numerator", "denominator"):
                    val = metric.get(key, "")
                    if val and not val.startswith("{{"):
                        measures.add(val)

            elif mtype == "conversion":
                entity = metric.get("entity", "")
                if entity:
                    entities.add(entity)

    return {"measures": list(measures), "models": list(models), "entities": list(entities)}


def _extract_measure_names_from_expr(expr: str) -> list[str]:
    """Extract bare identifier tokens from a derived metric expression.

    Example: ``"total_amount / user_count"`` → ``["total_amount", "user_count"]``
    """
    import re

    _SQL_KEYWORDS = {
        "select", "from", "where", "and", "or", "not", "in", "is", "null",
        "sum", "count", "avg", "min", "max", "case", "when", "then", "else",
        "end", "as", "on", "join", "left", "right", "inner", "outer",
        "true", "false", "cast", "coalesce", "if", "distinct",
    }
    tokens = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", expr)
    return [t for t in tokens if t.lower() not in _SQL_KEYWORDS]


def _extract_ref_name(ref: str) -> str:
    """Extract a model name from a dbt ``ref()`` call or plain string.

    Example: ``"ref('orders')"`` → ``"orders"``, ``"orders"`` → ``"orders"``
    """
    import re

    match = re.match(r"""ref\(\s*['"]([^'"]+)['"]\s*\)""", ref.strip())
    if match:
        return match.group(1)
    return ref.strip()


# ---------------------------------------------------------------------------
# Helpers: fallback providers (measure/model/entity might exist in
# another surviving file)
# ---------------------------------------------------------------------------

def _measure_provided_by(
    measure_name: str,
    except_file: str,
    active_files: dict[str, str],
    deleted_filename: str,
) -> bool:
    for fname, content in active_files.items():
        if fname in (deleted_filename, except_file):
            continue
        if not fname.endswith((".yml", ".yaml")):
            continue
        exports = _extract_exports(content)
        if measure_name in exports["measures"]:
            return True
    return False


def _model_provided_by(
    model_name: str,
    except_file: str,
    active_files: dict[str, str],
    deleted_filename: str,
) -> bool:
    for fname, content in active_files.items():
        if fname in (deleted_filename, except_file):
            continue
        if not fname.endswith((".yml", ".yaml")):
            continue
        exports = _extract_exports(content)
        if model_name in exports["models"]:
            return True
    return False


def _entity_provided_by(
    entity_name: str,
    except_file: str,
    active_files: dict[str, str],
    deleted_filename: str,
) -> bool:
    for fname, content in active_files.items():
        if fname in (deleted_filename, except_file):
            continue
        if not fname.endswith((".yml", ".yaml")):
            continue
        exports = _extract_exports(content)
        if entity_name in exports["entities"]:
            return True
    return False
