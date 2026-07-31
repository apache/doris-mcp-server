"""Entry point for doris-new-mcp server."""

import argparse
import os

from config.loader import AppConfig
from server import _decode_webui_session_cookie, create_server, get_machine_ip, resolve_machine_ip


def main() -> None:
    parser = argparse.ArgumentParser(description="doris-new-mcp: MCP Server for Apache Doris")
    parser.add_argument("--config-dir", default=os.environ.get("DORIS_MCP_CONFIG_DIR", "."))
    parser.add_argument("--env-file", default=None)
    args = parser.parse_args()

    cfg = AppConfig(args.config_dir, env_file=args.env_file)
    # Web UI node identity: ``privateIp`` pins ALL /mcp/web traffic (login
    # included) to one designated node — set the same value on every node.
    # Each node compares the target against its own detected address to
    # decide whether it IS the target; without a detectable address the
    # node assumes it is (single-node / offline behaviour unchanged).
    machine_ip = resolve_machine_ip(cfg.mcp.private_ip)
    force_target_ip = machine_ip if cfg.mcp.private_ip else None
    detected_ip = get_machine_ip()
    local_ip = detected_ip or machine_ip

    mcp = create_server(
        config_dir=args.config_dir,
        env_file=args.env_file,
        machine_ip=machine_ip,
        config=cfg,
    )

    from core.charset import CharsetMiddleware
    from core.session_affinity_proxy import SessionAffinityProxyMiddleware
    from core.request_logger import RequestLoggerMiddleware
    from starlette.middleware import Middleware
    mcp.run(
        transport="streamable-http",
        host=cfg.mcp.host,
        port=cfg.mcp.port,
        stateless_http=True,
        middleware=[
            Middleware(RequestLoggerMiddleware),
            Middleware(
                SessionAffinityProxyMiddleware,
                decoder=_decode_webui_session_cookie,
                local_ip=local_ip,
                target_port=cfg.mcp.port,
                force_target_ip=force_target_ip,
            ),
            Middleware(CharsetMiddleware),
        ],
    )


if __name__ == "__main__":
    main()
