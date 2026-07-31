from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from client import formatting


def _verbose_callback(value: bool):
    if value:
        os.environ["DORIS_MCP_DEBUG"] = "1"


app = typer.Typer(
    name="mcp-client",
    help="CLI client for mcp-server. Uses DORIS_MCP_SERVER + DORIS_MCP_TOKEN env vars or mcp-client.toml.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


@app.callback()
def main(
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", callback=_verbose_callback,
                     help="Show detailed error responses (tokens masked). "
                          "Equivalent to DORIS_MCP_DEBUG=1."),
    ] = False,
    config: Annotated[
        Optional[str],
        typer.Option("--config", "-c",
                     help="Path to mcp-client.toml config file."),
    ] = None,
):
    from client import config as cfg
    cfg.set_config_path(config)


tool_app = typer.Typer(
    help="MCP tool operations.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
semantic_app = typer.Typer(
    help="Semantic model management.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
app.add_typer(tool_app, name="tool")
app.add_typer(semantic_app, name="semantic")


# ---------------------------------------------------------------------------
# shared resolution
# ---------------------------------------------------------------------------

def _resolve() -> tuple[str, str]:
    """Resolve (server_url, token) from env vars or config file."""
    from client.config import resolve_token
    try:
        return resolve_token()
    except RuntimeError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# tool commands
# ---------------------------------------------------------------------------

@tool_app.command("list")
def tool_list():
    from client import mcp_client
    server_url, token = _resolve()
    try:
        tools = mcp_client.tool_list(server_url, token)
        formatting.print_tool_list(tools)
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@tool_app.command("describe")
def tool_describe(
    tool_name: Annotated[str, typer.Argument(help="Tool name")],
):
    from client import mcp_client
    server_url, token = _resolve()
    try:
        schema = mcp_client.tool_describe(server_url, token, tool_name)
        formatting.print_tool_schema(schema)
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@tool_app.command("call")
def tool_call(
    tool_name: Annotated[str, typer.Argument(help="Tool name")],
    arg: Annotated[Optional[list[str]], typer.Option("--arg", help="key=value argument")] = None,
    json_arg: Annotated[Optional[str], typer.Option("--json", help="Full JSON arguments")] = None,
):
    from client import mcp_client

    if arg and json_arg:
        typer.echo("Error: --arg and --json are mutually exclusive.", err=True)
        raise typer.Exit(1)

    arguments: dict = {}
    if json_arg:
        try:
            arguments = json.loads(json_arg)
        except json.JSONDecodeError as e:
            typer.echo(f"Error: invalid JSON: {e}", err=True)
            raise typer.Exit(1)
    elif arg:
        for a in arg:
            if "=" not in a:
                typer.echo(f"Error: argument must be key=value, got: {a}", err=True)
                raise typer.Exit(1)
            k, v = a.split("=", 1)
            try:
                arguments[k] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                arguments[k] = v

    server_url, token = _resolve()
    try:
        result = mcp_client.tool_call(server_url, token, tool_name, arguments)
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    if not formatting.print_tool_result(result):
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# semantic commands
# ---------------------------------------------------------------------------

@semantic_app.command("push")
def semantic_push(
    local_path: Annotated[str, typer.Argument(help="Local directory or file to upload")],
    workspace: Annotated[str, typer.Option("--workspace", "-w", help="Target workspace")] = "example",
):
    from client import http_client
    server_url, token = _resolve()
    try:
        result = http_client.semantic_push(server_url, token, local_path, workspace)
        data = result.get("data", {})
        rid = data.get("request_id", "?")
        typer.echo(
            f"Push accepted: {data.get('file_count', '?')} files, request_id={rid}"
        )
        typer.echo(
            f"Server is processing asynchronously. "
            f"Use 'mcp-client semantic result {rid}' to check."
        )
    except (RuntimeError, FileNotFoundError, ValueError) as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@semantic_app.command("result")
def semantic_result(
    request_id: Annotated[str, typer.Argument(help="request_id returned by 'semantic push'")],
):
    from client import http_client
    server_url, token = _resolve()
    try:
        result = http_client.semantic_result(server_url, token, request_id)
    except RuntimeError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    data = result.get("data", {}) if isinstance(result, dict) else {}
    state = data.get("state", "unknown")
    message = data.get("message", "")

    typer.echo(f"Request: {data.get('request_id', request_id)}")
    typer.echo(f"State:   {state}")
    if message:
        typer.echo(f"Message: {message}")

    if state == "success":
        raise typer.Exit(0)
    if state == "pending":
        raise typer.Exit(2)
    raise typer.Exit(1)


@semantic_app.command("pull")
def semantic_pull(
    output: Annotated[str, typer.Option("--output", help="Output directory")] = "./models",
    workspace: Annotated[str, typer.Option("--workspace", "-w", help="Source workspace")] = "example",
):
    from client import http_client
    server_url, token = _resolve()
    try:
        count = http_client.semantic_pull(server_url, token, output, workspace)
        typer.echo(f"Pulled {count} files to {output}/")
    except RuntimeError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@semantic_app.command("list")
def semantic_list(
    workspace: Annotated[str, typer.Option("--workspace", "-w", help="Target workspace")] = "example",
):
    from client import http_client
    server_url, token = _resolve()
    try:
        result = http_client.semantic_list_files(server_url, token, workspace)
    except RuntimeError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    files = result.get("data", []) if isinstance(result, dict) else []
    formatting.print_semantic_file_list(files)


@semantic_app.command("view")
def semantic_view(
    filename: Annotated[str, typer.Argument(help="Filename to view (e.g. orders.yaml)")],
    workspace: Annotated[str, typer.Option("--workspace", "-w", help="Target workspace")] = "example",
):
    from client import http_client
    server_url, token = _resolve()
    try:
        result = http_client.semantic_get_file(server_url, token, filename, workspace)
    except RuntimeError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    data = result.get("data", {}) if isinstance(result, dict) else {}
    if not data:
        typer.echo(f"File not found: {filename}", err=True)
        raise typer.Exit(1)
    typer.echo(data.get("content", ""))


@semantic_app.command("delete")
def semantic_delete(
    filename: Annotated[str, typer.Argument(help="Filename to delete (staging delete)")],
    force: Annotated[bool, typer.Option("--force", "-f", help="Skip confirmation")] = False,
    workspace: Annotated[str, typer.Option("--workspace", "-w", help="Target workspace")] = "example",
):
    if not force:
        confirm = typer.confirm(f"Stage '{filename}' for deletion?")
        if not confirm:
            raise typer.Exit(0)
    from client import http_client
    server_url, token = _resolve()
    try:
        result = http_client.semantic_delete_file(server_url, token, filename, workspace)
    except RuntimeError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    typer.echo(f"Staged for deletion: {filename}")


@semantic_app.command("edit")
def semantic_edit(
    filename: Annotated[str, typer.Argument(help="Filename to edit (e.g. orders.yaml)")],
    content: Annotated[Optional[str], typer.Option("--content", help="New content (inline)")] = None,
    file: Annotated[Optional[str], typer.Option("--file", help="Read content from file")] = None,
    workspace: Annotated[str, typer.Option("--workspace", "-w", help="Target workspace")] = "example",
):
    if content and file:
        typer.echo("Error: --content and --file are mutually exclusive.", err=True)
        raise typer.Exit(1)

    if content is not None:
        new_content = content
    elif file is not None:
        try:
            new_content = Path(file).read_text(encoding="utf-8")
        except Exception as e:
            typer.echo(f"Error reading file: {e}", err=True)
            raise typer.Exit(1)
    else:
        # Interactive: fetch current, open in $EDITOR
        from client import http_client
        server_url, token = _resolve()
        try:
            result = http_client.semantic_get_file(server_url, token, filename, workspace)
        except RuntimeError as e:
            typer.echo(f"Error: {e}", err=True)
            raise typer.Exit(1)
        data = result.get("data", {}) if isinstance(result, dict) else {}
        if not data:
            typer.echo(f"File not found: {filename}", err=True)
            raise typer.Exit(1)

        import tempfile, subprocess
        editor = os.environ.get("EDITOR", "vim")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tf:
            tf.write(data.get("content", ""))
            tmp_path = tf.name
        try:
            subprocess.run([editor, tmp_path], check=True)
            new_content = Path(tmp_path).read_text(encoding="utf-8")
        finally:
            os.unlink(tmp_path)

    from client import http_client
    server_url, token = _resolve()
    try:
        result = http_client.semantic_save_file(server_url, token, filename, new_content, workspace)
    except RuntimeError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    typer.echo(f"Saved: {filename}")


@semantic_app.command("reload")
def semantic_reload(
    workspace: Annotated[str, typer.Option("--workspace", "-w", help="Target workspace")] = "example",
):
    from client import http_client
    server_url, token = _resolve()
    try:
        result = http_client.semantic_reload(server_url, token, workspace)
        data = result.get("data", {})
        typer.echo(f"Reload {data.get('status', '?')}: {data.get('message', '')}")
    except RuntimeError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)


@semantic_app.command("status")
def semantic_status():
    from client import http_client
    server_url, token = _resolve()
    try:
        result = http_client.semantic_status(server_url, token)
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    if not formatting.print_semantic_status(result):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
