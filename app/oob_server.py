import asyncio
import secrets
import threading
import time
from datetime import datetime
from typing import Dict, Optional, Any
from aiohttp import web
import dns.message
import dns.rdatatype
import dns.rcode
import socket


class OOBServer:
    def __init__(self, domain: str = "oob.local", http_port: int = 8081, dns_port: int = 5353):
        self.domain = domain
        self.http_port = http_port
        self.dns_port = dns_port
        self.callbacks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._http_runner = None
        self._dns_thread = None
        self._running = False

    def generate_token(self) -> str:
        return secrets.token_urlsafe(16)

    def get_callback(self, token: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.callbacks.get(token)

    def _record_callback(self, token: str, callback_type: str, data: Dict[str, Any]):
        with self._lock:
            self.callbacks[token] = {
                "type": callback_type,
                "timestamp": datetime.utcnow().isoformat(),
                "data": data,
            }

    async def start(self):
        self._running = True

        app = web.Application()
        app.router.add_get("/{token}", self._handle_http_callback)
        app.router.add_post("/{token}", self._handle_http_callback)
        app.router.add_get("/{token}/", self._handle_http_callback)

        self._http_runner = web.AppRunner(app)
        await self._http_runner.setup()
        site = web.TCPSite(self._http_runner, "0.0.0.0", self.http_port)
        await site.start()

        self._dns_thread = threading.Thread(target=self._run_dns_server, daemon=True)
        self._dns_thread.start()

    async def stop(self):
        self._running = False
        if self._http_runner:
            await self._http_runner.cleanup()

    async def _handle_http_callback(self, request: web.Request) -> web.Response:
        token = request.match_info.get("token", "")
        if not token or "." in token:
            return web.Response(text="Not found", status=404)

        callback_data = {
            "method": request.method,
            "headers": dict(request.headers),
            "query": dict(request.query),
            "remote": request.remote,
        }

        try:
            body = await request.text()
            if body:
                callback_data["body"] = body
        except Exception:
            pass

        self._record_callback(token, "http", callback_data)

        return web.Response(text="OK", status=200)

    def _run_dns_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.dns_port))
        sock.settimeout(1.0)

        while self._running:
            try:
                data, addr = sock.recvfrom(512)
                request = dns.message.from_wire(data)

                for question in request.question:
                    qname = str(question.name).rstrip(".")
                    if qname.endswith(f".{self.domain}"):
                        token = qname.replace(f".{self.domain}", "")
                        if token and "." not in token:
                            self._record_callback(token, "dns", {
                                "qtype": dns.rdatatype.to_text(question.rdtype),
                                "remote": addr[0],
                            })

                response = dns.message.make_response(request)
                response.rcode = dns.rcode.NOERROR

                for question in request.question:
                    if str(question.name).rstrip(".").endswith(f".{self.domain}"):
                        token = str(question.name).rstrip(".").replace(f".{self.domain}", "")
                        if token and "." not in token:
                            response.answer.append(
                                dns.rrset.from_text(
                                    question.name, 300, "IN", "A", "127.0.0.1"
                                )
                            )

                sock.sendto(response.to_wire(), addr)
            except socket.timeout:
                continue
            except Exception:
                continue


_global_oob_server: Optional[OOBServer] = None


def get_oob_server() -> OOBServer:
    global _global_oob_server
    if _global_oob_server is None:
        from app.config import settings
        _global_oob_server = OOBServer(
            domain=settings.OOB_DOMAIN,
            http_port=settings.OOB_HTTP_PORT,
            dns_port=settings.OOB_DNS_PORT,
        )
    return _global_oob_server