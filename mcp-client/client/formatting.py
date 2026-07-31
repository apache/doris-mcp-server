from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


def print_tool_list(tools: list[dict[str, Any]]) -> None:
    table = Table(title="Available Tools")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")
    for t in tools:
        desc = t.get("description", "")
        if len(desc) > 80:
            desc = desc[:77] + "..."
        table.add_row(t["name"], desc)
    console.print(table)


def print_tool_schema(schema: dict[str, Any]) -> None:
    console.print(f"[cyan bold]{schema.get('name', '?')}[/]")
    if schema.get("description"):
        console.print(f"  {schema['description']}")
    console.print()
    input_schema = schema.get("inputSchema", {})
    if input_schema:
        console.print_json(json.dumps(input_schema, indent=2, ensure_ascii=False))


def _extract_tool_text(result: Any) -> tuple[str | None, bool]:
    if hasattr(result, "content"):
        content = getattr(result, "content", None)
        if content is not None:
            is_error = bool(
                getattr(result, "is_error", None)
                or getattr(result, "isError", False)
            )
            text_parts = []
            for block in content:
                text = getattr(block, "text", None)
                if text is not None:
                    text_parts.append(text)
            return ("\n".join(text_parts) if text_parts else None, is_error)

    if isinstance(result, str):
        return (result, False)

    if isinstance(result, (dict, list)):
        return (json.dumps(result, ensure_ascii=False), False)

    return (str(result), False)


def print_tool_result(result: Any) -> bool:
    text, is_error = _extract_tool_text(result)

    if text is None:
        console.print(str(result))
        return not is_error

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        console.print(text)
        return not is_error

    console.print_json(json.dumps(parsed, indent=2, ensure_ascii=False))

    if is_error:
        return False
    if isinstance(parsed, dict) and parsed.get("success") is False:
        return False
    return True


def print_semantic_status(result: Any) -> bool:
    text, is_error = _extract_tool_text(result)

    if is_error:
        if text:
            console.print(f"[red]Health check returned an error:[/]\n{text}")
        else:
            console.print("[red]Health check returned an error[/]")
        return False

    data = None
    if text:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            console.print(text)
            return False
    elif isinstance(result, dict):
        data = result

    if not data or not isinstance(data, dict):
        console.print("[yellow]Unable to parse status response[/]")
        return False

    inner = data.get("data", {}) if isinstance(data.get("data"), dict) else {}
    doris_status = inner.get("doris", "unknown")
    workspaces = inner.get("workspaces") if isinstance(inner.get("workspaces"), dict) else {}
    doris_error = inner.get("doris_error", "")

    d_style = "green" if doris_status == "connected" else "red"
    console.print(f"Doris: [bold {d_style}]{doris_status}[/]" + (f" \u2014 {doris_error}" if doris_error else ""))
    console.print()

    if not workspaces:
        console.print("[yellow]No workspaces found[/]")
        return True

    table = Table(title="Workspaces")
    table.add_column("Workspace", style="cyan", no_wrap=True)
    table.add_column("Status", style="white", no_wrap=True)
    table.add_column("Details", style="white")

    for ws_name, ws in sorted(workspaces.items()):
        if not isinstance(ws, dict):
            continue
        status = ws.get("status", "unknown")
        if status == "healthy":
            mc = ws.get("metric_count", 0)
            style = "green"
            details = f"{mc} metrics loaded"
        elif status == "no_models":
            style = "white"
            details = ws.get("message", "No YAML files")
        elif status == "not_ready":
            style = "red"
            details = ws.get("message", "Failed to load")
        else:
            style = "yellow"
            details = ws.get("message", "")
        table.add_row(ws_name, f"[{style}]{status}[/]", details)

    console.print(table)
    return True


def _print_component_table(components: dict, title: str) -> None:
    table = Table(title=title)
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Status", style="white", no_wrap=True)
    table.add_column("Details", style="white")
    for key, comp in components.items():
        if not isinstance(comp, dict):
            continue
        status = comp.get("status", "unknown")
        message = comp.get("message", "")
        style = "green" if status == "healthy" else ("yellow" if status == "degraded" else "red")
        table.add_row(key, f"[{style}]{status}[/]", message)
    console.print(table)


def print_semantic_file_list(files: list[dict[str, Any]]) -> None:
    if not files:
        console.print("[yellow]No semantic model files found.[/]")
        return
    table = Table(title="Semantic Model Files")
    table.add_column("Filename", style="cyan", no_wrap=True)
    table.add_column("Updated", style="white")
    table.add_column("Size", style="white", no_wrap=True)
    for f in files:
        size_kb = round((f.get("size_bytes", 0) or 0) / 1024, 1)
        table.add_row(f["filename"], f.get("updated_at", ""), f"{size_kb} KB")
    console.print(table)


def print_json_response(data: Any) -> None:
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            console.print(data)
            return
    console.print_json(json.dumps(data, indent=2, ensure_ascii=False))
