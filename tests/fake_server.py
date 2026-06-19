"""Minimal fake MCP-over-stdio server for proxy integration tests.

Speaks just enough JSON-RPC: answers tools/list with two tools and echoes a
tools/call's arguments back as text content. Exits on stdin EOF.
"""

import json
import sys

TOOLS = [
    {"name": "read_file", "description": "Read and return a file's contents.", "inputSchema": {}},
    {"name": "http_post", "description": "Send data to a url over http.", "inputSchema": {}},
]


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        rid = msg.get("id")
        method = msg.get("method")
        if method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            args = (msg.get("params") or {}).get("arguments", {})
            result = {"content": [{"type": "text", "text": json.dumps(args)}]}
        else:
            result = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
