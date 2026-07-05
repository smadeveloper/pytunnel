"""
WebSocket Reverse Tunnel Server
================================
Runs on the VPS. Forwards incoming HTTP requests to the tunnel client
over a WebSocket connection, and relays responses back.

Usage:
    pip install aiohttp
    python server.py --secret YOUR_SECRET

Systemd service example:
    [Unit]
    Description=Tunnel Server
    After=network.target

    [Service]
    Type=simple
    User=www-data
    WorkingDirectory=/opt/tunnel
    ExecStart=/usr/bin/python3 /opt/tunnel/server.py --secret YOUR_SECRET --port 9000
    Restart=always
    RestartSec=5

    [Install]
    WantedBy=multi-user.target
"""

import argparse
import asyncio
import base64
import json
import logging
import uuid

from aiohttp import web, WSMsgType

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("tunnel-server")

# ── Hop-by-hop and proxy headers that must not be forwarded ─────────────────
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "expect",
})

# Additional headers to strip from responses (aiohttp sets these automatically)
RESPONSE_FILTER = HOP_BY_HOP | frozenset({"content-length", "server"})


# ── Global state ─────────────────────────────────────────────────────────────
class TunnelState:
    """Holds the single active tunnel connection and pending request futures."""

    def __init__(self, secret: str):
        self.secret = secret
        self.ws: web.WebSocketResponse | None = None
        self.pending: dict[str, asyncio.Future] = {}
        self._lock = asyncio.Lock()          # for ws set/replace

    @property
    def connected(self) -> bool:
        return self.ws is not None and not self.ws.closed


# ── WebSocket handler: tunnel client connects here ──────────────────────────
async def ws_tunnel_handler(request: web.Request) -> web.WebSocketResponse:
    state: TunnelState = request.app["tunnel_state"]

    # Auth check
    if request.query.get("secret") != state.secret:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.close(code=4001, message=b"Unauthorized")
        logger.warning("Unauthorized tunnel connection attempt")
        return ws

    ws = web.WebSocketResponse(max_msg_size=50 * 1024 * 1024, heartbeat=30)
    await ws.prepare(request)

    async with state._lock:
        # Replace any existing connection
        if state.ws is not None and not state.ws.closed:
            logger.info("Replacing existing tunnel connection")
            await state.ws.close(code=4002, message=b"Replaced by new connection")
        state.ws = ws

    logger.info("✅ Tunnel client connected")

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON message received")
                    continue

                if data.get("type") == "response":
                    req_id = data.get("id")
                    if req_id and req_id in state.pending:
                        state.pending[req_id].set_result(data)
                        del state.pending[req_id]
                    else:
                        logger.debug("Unknown response ID: %s", req_id)

                elif data.get("type") == "ping":
                    await ws.send_str(json.dumps({"type": "pong"}))

            elif msg.type == WSMsgType.ERROR:
                logger.error("WebSocket error: %s", ws.exception())
                break

            elif msg.type == WSMsgType.CLOSED:
                break
    finally:
        async with state._lock:
            if state.ws is ws:                     # Still our connection?
                state.ws = None
                # Fail all pending requests
                for req_id, future in list(state.pending.items()):
                    if not future.done():
                        future.set_exception(ConnectionError("Tunnel disconnected"))
                state.pending.clear()
        logger.info("❌ Tunnel client disconnected")

    return ws


# ── HTTP proxy handler: forwards internet requests through the tunnel ───────
async def http_proxy_handler(request: web.Request) -> web.Response:
    state: TunnelState = request.app["tunnel_state"]

    if not state.connected:
        return web.Response(
            status=502,
            content_type="text/plain",
            text="502 Bad Gateway — Tunnel not connected",
        )

    req_id = str(uuid.uuid4())

    # ── Read body ────────────────────────────────────────────────────────
    try:
        raw_body = await request.read()
    except Exception:
        return web.Response(status=400, text="400 Bad Request — Could not read body")

    body_b64 = base64.b64encode(raw_body).decode() if raw_body else ""

    # ── Collect headers (skip hop-by-hop and host) ───────────────────────
    headers: list[list[str]] = []
    for key, value in request.headers.items():
        lk = key.lower()
        if lk not in HOP_BY_HOP and lk != "host":
            headers.append([key, value])

    # Add forwarding headers if not already present (Nginx may have added them)
    existing_lower = {k.lower() for k, _ in headers}
    if "x-forwarded-for" not in existing_lower:
        headers.append(["X-Forwarded-For", request.remote or ""])
    if "x-forwarded-proto" not in existing_lower:
        headers.append(["X-Forwarded-Proto", request.scheme])
    if "x-forwarded-host" not in existing_lower:
        headers.append(["X-Forwarded-Host", request.host])

    # ── Build tunnel message ─────────────────────────────────────────────
    msg = {
        "type": "request",
        "id": req_id,
        "method": request.method,
        "raw_path": request.raw_path,          # Preserves URL encoding
        "query_string": request.query_string,
        "headers": headers,
        "body": body_b64,
    }

    # ── Create future and send ───────────────────────────────────────────
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    state.pending[req_id] = future

    try:
        await state.ws.send_str(json.dumps(msg))
    except Exception as exc:
        state.pending.pop(req_id, None)
        logger.error("Failed to send message over WebSocket: %s", exc)
        return web.Response(status=502, text="502 Bad Gateway — Cannot write to tunnel")

    # ── Wait for response ────────────────────────────────────────────────
    try:
        result = await asyncio.wait_for(future, timeout=120)
    except asyncio.TimeoutError:
        state.pending.pop(req_id, None)
        return web.Response(status=504, text="504 Gateway Timeout")
    except ConnectionError:
        state.pending.pop(req_id, None)
        return web.Response(status=502, text="502 Bad Gateway — Tunnel disconnected")
    except Exception as exc:
        state.pending.pop(req_id, None)
        logger.exception("Unexpected error while waiting for response")
        return web.Response(status=500, text=f"500 Internal Server Error — {exc}")

    # ── Convert client response to HTTP response ─────────────────────────
    resp_body = base64.b64decode(result.get("body", "")) if result.get("body") else b""

    response = web.Response(status=result.get("status_code", 502), body=resp_body)

    for key, value in result.get("headers", []):
        if key.lower() not in RESPONSE_FILTER:
            response.headers.add(key, value)

    return response


# ── Status endpoint ──────────────────────────────────────────────────────────
async def tunnel_status_handler(request: web.Request) -> web.Response:
    state: TunnelState = request.app["tunnel_state"]
    return web.json_response({
        "tunnel_connected": state.connected,
        "pending_requests": len(state.pending),
    })


# ── Application factory ─────────────────────────────────────────────────────
async def on_shutdown(app: web.Application):
    """Graceful shutdown: close the WebSocket connection."""
    state: TunnelState = app["tunnel_state"]
    if state.ws and not state.ws.closed:
        await state.ws.close(code=1001, message=b"Server shutting down")


def create_app(secret: str) -> web.Application:
    app = web.Application()
    app["tunnel_state"] = TunnelState(secret)

    # Specific routes must be registered BEFORE the catch-all
    app.router.add_get("/ws/tunnel", ws_tunnel_handler)
    app.router.add_get("/tunnel-status", tunnel_status_handler)
    app.router.add_route("*", "/{path:.*}", http_proxy_handler)

    app.on_shutdown.append(on_shutdown)
    return app


def main():
    parser = argparse.ArgumentParser(description="WebSocket Reverse Tunnel Server")
    parser.add_argument("--secret", required=True, help="Tunnel client auth secret")
    parser.add_argument("--host", default="127.0.0.1", help="Listen host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Listen port (default: 9000)")
    args = parser.parse_args()

    app = create_app(args.secret)
    logger.info("🚀 Tunnel server starting on %s:%d…", args.host, args.port)
    web.run_app(app, host=args.host, port=args.port, print=logger.info)


if __name__ == "__main__":
    main()
