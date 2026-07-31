# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Generate the checked-in 1.0 domain and child tool catalog."""

from __future__ import annotations

import argparse
from pathlib import Path

from doris_mcp_server.tools.domain_catalog import DORIS_DOMAIN_CATALOG

REPOSITORY_ROOT = Path(__file__).resolve().parent
OUTPUT_PATH = REPOSITORY_ROOT / "docs" / "tool-registry.md"


def render_catalog() -> str:
    """Render the exact catalog source of truth with a terminal newline."""
    return DORIS_DOMAIN_CATALOG.render_markdown()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the Doris MCP Server 1.0 tool catalog."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when the checked-in catalog differs from the source.",
    )
    args = parser.parse_args()
    rendered = render_catalog()

    if args.check:
        if not OUTPUT_PATH.exists() or OUTPUT_PATH.read_text(
            encoding="utf-8"
        ) != rendered:
            parser.error(
                "docs/tool-registry.md is stale; run generate_tool_catalog.py"
            )
        return 0

    OUTPUT_PATH.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
