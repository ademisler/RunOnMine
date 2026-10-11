#!/usr/bin/env python3
"""Protocol-level MCP Streamable HTTP acceptance client."""
from __future__ import annotations

import argparse
import http.client
import json
import socket
import sys
import time
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

PROTOCOL_VERSION = "2025-06-18"
MAX_BODY = 2 * 1024 * 1024


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def connection(parts):
    if parts.scheme != "http" or parts.hostname not in {"127.0.0.1", "localhost", "::1"}:
        fail("acceptance client only permits loopback HTTP")
    return http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)


def json_from_sse(response: http.client.HTTPResponse, expected_id: int | None) -> dict[str, Any]:
    consumed = 0
    data_lines: list[str] = []
    while True:
        line = response.readline(MAX_BODY + 1)
        if not line:
            fail("SSE stream ended before a JSON-RPC response")
        consumed += len(line)
        if consumed > MAX_BODY:
            fail("SSE response exceeded the acceptance limit")
        decoded = line.decode("utf-8", errors="strict").rstrip("\r\n")
        if decoded == "":
            if not data_lines:
                continue
            payload = "\n".join(data_lines)
            data_lines.clear()
            if not payload.strip():
                continue
            message = json.loads(payload)
            if expected_id is None or message.get("id") == expected_id:
                return message
            continue
        if decoded.startswith("data:"):
            data_lines.append(decoded[5:].lstrip())


def decode_response(response: http.client.HTTPResponse, expected_id: int | None) -> dict[str, Any] | None:
    content_type = response.getheader("content-type", "").split(";", 1)[0].strip().lower()
    if response.status == 202:
        response.read(MAX_BODY)
        return None
    if response.status < 200 or response.status >= 300:
        body = response.read(MAX_BODY).decode("utf-8", errors="replace")
        fail(f"HTTP {response.status}: {body[:500]}")
    if content_type == "application/json":
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            fail("JSON response exceeded the acceptance limit")
        if not body.strip() and expected_id is None:
            return None
        message = json.loads(body)
        if expected_id is not None and message.get("id") != expected_id:
            fail(f"unexpected JSON-RPC id: {message.get('id')!r}")
        return message
    if content_type == "text/event-stream":
        return json_from_sse(response, expected_id)
    fail(f"unexpected MCP response content type: {content_type!r}")


def request(parts, token: str, payload: dict[str, Any] | bytes, *, session: str | None = None,
            expected_id: int | None = None, method: str = "POST") -> tuple[dict[str, Any] | None, str | None, int]:
    conn = connection(parts)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Host": parts.netloc,
    }
    if session:
        headers["Mcp-Session-Id"] = session
        headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
    body = payload if isinstance(payload, bytes) else json.dumps(payload, separators=(",", ":")).encode()
    try:
        conn.request(method, parts.path or "/mcp", body=body if method != "DELETE" else None, headers=headers)
        response = conn.getresponse()
        session_id = response.getheader("mcp-session-id")
        status = response.status
        message = decode_response(response, expected_id)
        return message, session_id, status
    finally:
        conn.close()


def expect_error_status(parts, token: str, expected: set[int], payload: bytes) -> None:
    conn = connection(parts)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Host": parts.netloc,
    }
    try:
        conn.request("POST", parts.path or "/mcp", body=payload, headers=headers)
        response = conn.getresponse()
        response.read(MAX_BODY)
        if response.status not in expected:
            fail(f"expected HTTP {sorted(expected)}, received {response.status}")
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--approval-write-path")
    args = parser.parse_args()
    if args.iterations < 1 or args.iterations > 100_000:
        fail("iterations must be between 1 and 100000")
    stage = "load_credential"
    parts = urlsplit(args.url)
    credential = json.loads(Path(args.token_file).read_text())
    token = credential.get("bearer_token")
    if not isinstance(token, str) or len(token) < 32:
        fail("credential file has no valid bearer_token")

    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "runonmine-acceptance", "version": "1"},
        },
    }
    stage = "initialize"
    try:
        message, session, _ = request(parts, token, initialize, expected_id=1)
    except (RuntimeError, OSError, socket.timeout) as error:
        fail(f"initialize: {error}")
    if not session:
        fail("initialize response did not include Mcp-Session-Id")
    if not message or "result" not in message:
        fail(f"initialize failed: {message!r}")
    negotiated = message["result"].get("protocolVersion")
    if not isinstance(negotiated, str):
        fail("initialize result has no protocolVersion")

    stage = "initialized_notification"
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    try:
        request(parts, token, initialized, session=session)
    except (RuntimeError, OSError, socket.timeout) as error:
        fail(f"initialized notification: {error}")

    stage = "tools_list"
    tools: list[dict[str, Any]] = []
    for iteration in range(args.iterations):
        if iteration and iteration % 100 == 0:
            print(f"mcp soak progress: {iteration}/{args.iterations}", file=sys.stderr)
        request_id = 2 + iteration
        listed = None
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                listed, _, _ = request(
                    parts,
                    token,
                    {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}},
                    session=session,
                    expected_id=request_id,
                )
                break
            except (RuntimeError, OSError, socket.timeout) as error:
                last_error = error
                if attempt < 2:
                    time.sleep(0.05 * (attempt + 1))
        if listed is None:
            fail(f"tools/list iteration {iteration + 1}/{args.iterations}: {last_error}")
        current = listed.get("result", {}).get("tools", []) if listed else []
        if iteration == 0:
            tools = current
            names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
            if "machine_info" not in names:
                fail(f"machine_info missing from tools/list: {sorted(str(n) for n in names)}")

    stage = "machine_info"
    try:
        called, _, _ = request(
            parts,
            token,
            {
                "jsonrpc": "2.0",
                "id": args.iterations + 2,
                "method": "tools/call",
                "params": {"name": "machine_info", "arguments": {}},
            },
            session=session,
            expected_id=args.iterations + 2,
        )
    except (RuntimeError, OSError, socket.timeout) as error:
        fail(f"machine_info after {args.iterations} tools/list requests: {error}")
    if not called or "result" not in called or called["result"].get("isError") is True:
        fail(f"machine_info call failed: {called!r}")

    stage = "denied_admin_exec"
    admin_id = args.iterations + 3
    try:
        denied_admin, _, _ = request(
            parts,
            token,
            {
                "jsonrpc": "2.0",
                "id": admin_id,
                "method": "tools/call",
                "params": {
                    "name": "admin_exec",
                    "arguments": {
                        "program": "/bin/true",
                        "args": [],
                    },
                },
            },
            session=session,
            expected_id=admin_id,
        )
    except (RuntimeError, OSError, socket.timeout) as error:
        fail(f"denied admin_exec: {error}")
    admin_denied = bool(
        denied_admin
        and (
            "error" in denied_admin
            or denied_admin.get("result", {}).get("isError") is True
        )
    )
    if not admin_denied:
        fail(f"admin_exec was not denied: {denied_admin!r}")

    approved_write = False
    if args.approval_write_path:
        stage = "approved_fs_write"
        write_id = args.iterations + 4
        try:
            written, _, _ = request(
                parts,
                token,
                {
                    "jsonrpc": "2.0",
                    "id": write_id,
                    "method": "tools/call",
                    "params": {
                        "name": "fs_write",
                        "arguments": {
                            "path": args.approval_write_path,
                            "content": "approved MCP acceptance write\n",
                        },
                    },
                },
                session=session,
                expected_id=write_id,
            )
        except (RuntimeError, OSError, socket.timeout) as error:
            fail(f"approved fs_write: {error}")
        if not written or "result" not in written or written["result"].get("isError") is True:
            fail(f"approved fs_write failed: {written!r}")
        expected = "approved MCP acceptance write\n"
        if Path(args.approval_write_path).read_text() != expected:
            fail("approved fs_write did not produce the expected file content")
        approved_write = True

    stage = "negative_auth"
    expect_error_status(parts, "invalid-token", {401}, json.dumps(initialize).encode())
    stage = "malformed_body"
    expect_error_status(parts, token, {400, 415, 422}, b"{")

    stage = "session_delete"
    try:
        _, _, delete_status = request(parts, token, b"", session=session, method="DELETE")
    except (RuntimeError, OSError, socket.timeout) as error:
        fail(f"session delete after {args.iterations} tools/list requests: {error}")
    if delete_status not in {200, 202, 204}:
        fail(f"session delete returned HTTP {delete_status}")

    print(json.dumps({
        "status": "passed",
        "protocol_version": negotiated,
        "tool_count": len(tools),
        "safe_tool_call": "machine_info",
        "session_deleted": True,
        "list_iterations": args.iterations,
        "approved_write": approved_write,
        "denied_admin_call": admin_denied,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, socket.timeout, ValueError, json.JSONDecodeError) as error:
        print(f"MCP HTTP acceptance failed: {error}", file=sys.stderr)
        raise SystemExit(1)
