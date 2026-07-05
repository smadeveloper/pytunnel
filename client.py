"""
WebSocket Reverse Tunnel Client
================================
Runs on the local machine. Connects to the VPS tunnel server via WebSocket,
forwards incoming HTTP requests to localhost:8000, and sends responses back.

Usage:
    pip install aiohttp
    python client.py --secret YOUR_SECRET --server wss://subdomain.example.com/ws/tunnel --local http://localhost:8000

Background example:
    nohup python client.py --secret YOUR_SECRET &

Systemd service example:
    [Unit]
    Description=Tunnel Client
    After=network.target

    [Service]
    Type=simple
    User=youruser
    WorkingDirectory=/opt/tunnel-client
    ExecStart=/usr/bin/python3 /opt/tunnel-client/client.py --secret YOUR_SECRET --local http://localhost:8000
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
import signal

import aiohttp
from yarl import URL

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("tunnel-client")

# ── Header filtering ────────────────────────────────────────────────────────
# Headers that must not be forwarded by a proxy
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "expect",
})

REQUEST_FILTER = HOP_BY_HOP | frozenset({"host"})
RESPONSE_FILTER = HOP_BY_HOP | frozenset({"content-length", "transfer-encoding"})


class TunnelClient:
    """
    Connects to the VPS tunnel server via WebSocket.
    Forwards incoming HTTP requests to the local server,
    and relays responses back over the WebSocket.
    """

    def __init__(self, server_url: str, local_base: str, secret: str):
        self.server_url = server_url
        self.local_base = local_base.rstrip("/")
        self.secret = secret

        self.session: aiohttp.ClientSession | None = None
        self.ws: aiohttp.ClientWebSocketResponse | None = None

        self._reconnect_delay = 1.0       # seconds
        self._max_delay = 30.0
        self._running = True
        self._pending_tasks: dict[str, asyncio.Task] = {}

    # ── Main loop ────────────────────────────────────────────────────────
    async def start(self):
        self.session = aiohttp.ClientSession(
            auto_decompress=False,   # Preserve Content-Encoding as-is
            timeout=aiohttp.ClientTimeout(total=120),
        )
        try:
            while self._running:
                try:
                    await self._connect_and_serve()
                except (aiohttp.ClientError, ConnectionError, OSError) as exc:
                    logger.warning("Connection error: %s", exc)
                except Exception as exc:
                    logger.exception("Unexpected error: %s", exc)

                if self._running:
                    logger.info("⏳ Reconnecting in %g seconds…", self._reconnect_delay)
                    await asyncio.sleep(self._reconnect_delay)
                    self._reconnect_delay = min(self._reconnect_delay * 2, self._max_delay)
        finally:
            await self.session.close()

    async def stop(self):
        logger.info("Shutting down…")
        self._running = False
        if self.ws and not self.ws.closed:
            await self.ws.close()
        # Cancel pending tasks
        for task in self._pending_tasks.values():
            task.cancel()
        if self._pending_tasks:
            await asyncio.gather(*self._pending_tasks.values(), return_exceptions=True)

    # ── WebSocket connection ─────────────────────────────────────────────
    async def _connect_and_serve(self):
        url = f"{self.server_url}?secret={self.secret}"
        logger.info("🔗 Connecting to %s…", self.server_url)

        async with self.session.ws_connect(
            url,
            heartbeat=30,                       # Ping every 30 seconds
            max_msg_size=50 * 1024 * 1024,      # 50 MB
            receive_timeout=90,                  # Timeout if no message in 90s
        ) as ws:
            self.ws = ws
            self._reconnect_delay = 1.0         # Reset on successful connection
            logger.info("✅ Connected to tunnel server!")

            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await self._on_text_message(msg.data)
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error("WebSocket error: %s", ws.exception())
                    break
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    break

            self.ws = None

    # ── Handle incoming messages ─────────────────────────────────────────
    async def _on_text_message(self, raw: str):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Invalid JSON message")
            return

        if data.get("type") == "request":
            req_id = data["id"]
            task = asyncio.create_task(self._handle_request(data))
            self._pending_tasks[req_id] = task
            task.add_done_callback(lambda t, rid=req_id: self._pending_tasks.pop(rid, None))

        elif data.get("type") == "pong":
            pass  # Heartbeat response, nothing to do

        else:
            logger.debug("Unknown message type: %s", data.get("type"))

    # ── Forward incoming HTTP request to local server ────────────────────
    async def _handle_request(self, data: dict):
        req_id = data["id"]
        method = data["method"]
        raw_path = data.get("raw_path", "/")
        query_string = data.get("query_string", "")

        # Build URL (raw_path preserves URL encoding)
        url_str = f"{self.local_base}{raw_path}"
        if query_string:
            url_str += f"?{query_string}"

        try:
            url = URL(url_str, encoded=True)
        except Exception:
            url = URL(url_str)

        # Body
        body = base64.b64decode(data["body"]) if data.get("body") else None

        # Prepare headers (skip host and hop-by-hop)
        headers: dict[str, str] = {}
        for key, value in data.get("headers", []):
            if key.lower() not in REQUEST_FILTER:
                headers[key] = value
        headers["Host"] = "localhost"

        # ── Send request to local server ─────────────────────────────────
        try:
            async with self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=body,
                allow_redirects=False,   # Pass redirects through as-is
                ssl=False,               # localhost HTTP
            ) as resp:
                resp_body = await resp.read()
                resp_body_b64 = base64.b64encode(resp_body).decode() if resp_body else ""

                # Response headers as list (supports duplicates like Set-Cookie)
                resp_headers: list[list[str]] = []
                for key, value in resp.headers.items():
                    if key.lower() not in RESPONSE_FILTER:
                        resp_headers.append([key, value])

                response_msg = {
                    "type": "response",
                    "id": req_id,
                    "status_code": resp.status,
                    "headers": resp_headers,
                    "body": resp_body_b64,
                }

        except asyncio.TimeoutError:
            response_msg = {
                "type": "response",
                "id": req_id,
                "status_code": 504,
                "headers": [["Content-Type", "text/plain"]],
                "body": base64.b64encode(b"Local server timeout (60s)").decode(),
            }
            logger.warning("⏰ Local server timeout — %s %s", method, raw_path)

        except (ConnectionError, OSError) as exc:
            response_msg = {
                "type": "response",
                "id": req_id,
                "status_code": 502,
                "headers": [["Content-Type", "text/plain"]],
                "body": base64.b64encode(
                    f"Local server connection error: {exc}".encode()
                ).decode(),
            }
            logger.error("🔌 Local server unreachable: %s", exc)

        except Exception as exc:
            response_msg = {
                "type": "response",
                "id": req_id,
                "status_code": 500,
                "headers": [["Content-Type", "text/plain"]],
                "body": base64.b64encode(f"Internal error: {exc}".encode()).decode(),
            }
            logger.exception("⚠️ Error processing request: %s", req_id)

        # ── Send response back over WebSocket ────────────────────────────
        if self.ws and not self.ws.closed:
            try:
                await self.ws.send_str(json.dumps(response_msg))
            except Exception as exc:
                logger.error("Failed to send response (%s): %s", req_id, exc)


# ── Entry point ──────────────────────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser(description="WebSocket Reverse Tunnel Client")
    parser.add_argument(
        "--secret", required=True,
        help="Tunnel auth secret (must match the server)",
    )
    parser.add_argument(
        "--server", default="wss://subdomain.example.com/ws/tunnel",
        help="Tunnel server WebSocket URL",
    )
    parser.add_argument(
        "--local", default="http://localhost:8000",
        help="Local server base URL",
    )
    args = parser.parse_args()

    client = TunnelClient(
        server_url=args.server,
        local_base=args.local,
        secret=args.secret,
    )

    # ── Signal handling (graceful shutdown) ──────────────────────────────
    loop = asyncio.get_running_loop()
    stop_future = loop.create_future()

    def _signal_handler():
        if not stop_future.done():
            stop_future.set_result(None)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # add_signal_handler is not available on Windows
            pass

    # ── Start ────────────────────────────────────────────────────────────
    task = asyncio.create_task(client.start())
    logger.info("🚀 Tunnel client started — %s → %s", args.local, args.server)

    await stop_future
    await client.stop()

    try:
        await asyncio.wait_for(task, timeout=10)
    except asyncio.TimeoutError:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(main())
