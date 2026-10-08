"""SIP transports (UDP server, TCP/TLS client connection) and transaction layer."""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time

from .message import (SipMessage, StreamParser, Via, gen_branch, make_response,
                      parse_message)

log = logging.getLogger("rcproxy.sip")
trace = logging.getLogger("rcproxy.trace")

T1, T2, T4 = 0.5, 4.0, 5.0
TIMER_B = 64 * T1  # 32 s


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------

class UdpTransport(asyncio.DatagramProtocol):
    proto = "UDP"
    reliable = False

    def __init__(self, on_message, sent_by):
        self.on_message = on_message
        self._sent_by = sent_by           # callable -> (host, port)
        self.transport: asyncio.DatagramTransport | None = None
        self.name = "phones"

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if not data.strip(b"\r\n\x00 "):
            return  # keep-alive
        try:
            msg = parse_message(data)
        except Exception as e:  # noqa: BLE001
            log.debug("UDP: unparseable packet from %s:%s: %s", addr[0], addr[1], e)
            return
        trace.debug("RECV from %s:%s (UDP)\n%s", addr[0], addr[1], data.decode("utf-8", "replace"))
        self.on_message(msg, addr)

    def error_received(self, exc):
        log.debug("UDP error: %s", exc)

    def send(self, data: bytes, addr):
        if self.transport is None or addr is None:
            return
        trace.debug("SEND to %s:%s (UDP)\n%s", addr[0], addr[1], data.decode("utf-8", "replace"))
        self.transport.sendto(data, addr)

    @property
    def sent_by(self):
        return self._sent_by()


def make_ssl_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # RingCentral SBCs prefer finite-field DHE with parameters that OpenSSL 3
    # rejects (DH_KEY_TOO_SMALL); excluding DHE makes them choose RSA/ECDHE.
    ctx.set_ciphers("DEFAULT:!kDHE")
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class StreamConnection:
    """A single outbound TCP or TLS connection (one per RingCentral endpoint)."""

    reliable = True
    KEEPALIVE = 30.0

    def __init__(self, name: str, on_message, on_closed):
        self.name = name
        self.on_message = on_message
        self.on_closed = on_closed
        self.proto = "TCP"
        self.reader = self.writer = None
        self.local = ("0.0.0.0", 0)
        self.peer = None
        self.closed = True
        self._tasks: list[asyncio.Task] = []
        self.last_rx = 0.0
        self.connected_at = 0.0

    async def open(self, host: str, port: int, tls: bool, verify: bool = True,
                   timeout: float = 10.0):
        self.proto = "TLS" if tls else "TCP"
        ctx = make_ssl_context(verify) if tls else None
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host if tls else None),
            timeout)
        sock = self.writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
        self.local = self.writer.get_extra_info("sockname")[:2]
        self.peer = self.writer.get_extra_info("peername")[:2]
        self.closed = False
        self.last_rx = self.connected_at = time.time()
        tls_ver = ""
        if tls:
            sslobj = self.writer.get_extra_info("ssl_object")
            tls_ver = f" ({sslobj.version()}, {sslobj.cipher()[0]})" if sslobj else ""
        log.info("[%s] connected %s %s:%s -> %s:%s%s", self.name, self.proto, self.local[0],
                 self.local[1], self.peer[0], self.peer[1], tls_ver)
        self._tasks = [asyncio.create_task(self._read_loop()),
                       asyncio.create_task(self._keepalive_loop())]

    @property
    def sent_by(self):
        return self.local

    async def _read_loop(self):
        parser = StreamParser()
        reason = "closed by peer"
        try:
            while True:
                data = await self.reader.read(65536)
                if not data:
                    break
                self.last_rx = time.time()
                for kind, raw in parser.feed(data):
                    if kind == "ping":
                        self._write(b"\r\n")
                    elif kind == "msg":
                        trace.debug("RECV from %s:%s (%s)\n%s", self.peer[0], self.peer[1],
                                    self.proto, raw.decode("utf-8", "replace"))
                        try:
                            msg = parse_message(raw)
                        except Exception as e:  # noqa: BLE001
                            log.warning("[%s] bad SIP message: %s", self.name, e)
                            continue
                        try:
                            self.on_message(msg, self.peer)
                        except Exception:  # noqa: BLE001
                            log.exception("[%s] error handling message", self.name)
        except asyncio.CancelledError:
            reason = "closed locally"
            raise
        except Exception as e:  # noqa: BLE001
            reason = f"error: {e}"
        finally:
            self._finish(reason)

    async def _keepalive_loop(self):
        try:
            while not self.closed:
                await asyncio.sleep(self.KEEPALIVE)
                self._write(b"\r\n\r\n")
        except (asyncio.CancelledError, ConnectionError):
            pass
        except Exception as e:  # noqa: BLE001
            self._finish(f"keepalive error: {e}")

    def _write(self, data: bytes):
        if self.closed or self.writer is None:
            raise ConnectionError("connection closed")
        self.writer.write(data)

    def send(self, data: bytes, addr=None):
        trace.debug("SEND to %s:%s (%s)\n%s", self.peer[0] if self.peer else "?",
                    self.peer[1] if self.peer else "?", self.proto,
                    data.decode("utf-8", "replace"))
        self._write(data)

    def _finish(self, reason: str):
        if self.closed and not self._tasks:
            return
        was_open = not self.closed
        self.closed = True
        for t in self._tasks:
            if t is not asyncio.current_task():
                t.cancel()
        self._tasks = []
        try:
            if self.writer is not None:
                self.writer.close()
        except Exception:  # noqa: BLE001
            pass
        if was_open:
            log.info("[%s] connection %s", self.name, reason)
            try:
                self.on_closed(self, reason)
            except Exception:  # noqa: BLE001
                log.exception("on_closed handler failed")

    def close(self):
        self._finish("closed locally")


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------

class ClientTransaction:
    def __init__(self, layer: "TransactionLayer", msg: SipMessage, addr, callback,
                 timeout: float | None):
        self.layer = layer
        self.msg = msg
        self.addr = addr
        self.callback = callback
        self.method = msg.cseq[1]
        self.branch = msg.top_via.branch
        self.key = (self.branch, self.method)
        self.state = "calling"
        self.final: SipMessage | None = None
        self.ack: SipMessage | None = None
        self._timeout_s = timeout if timeout is not None else TIMER_B
        self._timeout_h = None
        self._rt_task = None

    def start(self):
        loop = asyncio.get_running_loop()
        try:
            self.layer.send_msg(self.msg, self.addr)
        except Exception as e:  # noqa: BLE001
            log.warning("[%s] send failed: %s", self.layer.name, e)
            loop.call_soon(self._fail, 503, "Service Unavailable")
            return
        if not self.layer.reliable:
            self._rt_task = asyncio.create_task(self._retransmit())
        self._timeout_h = loop.call_later(self._timeout_s, self._fail, 408, "Request Timeout")

    async def _retransmit(self):
        interval = T1
        try:
            while True:
                await asyncio.sleep(interval)
                if self.state in ("completed", "terminated"):
                    return
                if self.method == "INVITE" and self.state == "proceeding":
                    return
                self.layer.send_msg(self.msg, self.addr)
                if self.method == "INVITE":
                    interval *= 2
                else:
                    interval = T2 if self.state == "proceeding" else min(interval * 2, T2)
        except asyncio.CancelledError:
            pass
        except Exception as e:  # noqa: BLE001
            log.debug("retransmit failed: %s", e)

    def _stop_timers(self):
        if self._timeout_h:
            self._timeout_h.cancel()
            self._timeout_h = None
        if self._rt_task:
            self._rt_task.cancel()
            self._rt_task = None

    def _fail(self, status, reason):
        if self.state in ("completed", "terminated"):
            return
        self.state = "terminated"
        self._stop_timers()
        self.layer._remove_client(self)
        resp = make_response(self.msg, status, reason)
        resp.synthetic = True
        self._deliver(resp)

    def _deliver(self, resp):
        try:
            self.callback(resp)
        except Exception:  # noqa: BLE001
            log.exception("response callback failed")

    def cancel(self):
        """Stop the transaction silently (no callback)."""
        self.state = "terminated"
        self._stop_timers()
        self.layer._remove_client(self)

    def on_response(self, resp: SipMessage):
        status = resp.status
        if self.state in ("completed", "terminated"):
            if status >= 200 and self.method == "INVITE":
                if status >= 300 and self.ack is not None:
                    self.layer.send_msg(self.ack, self.addr)
                elif status < 300:
                    self._deliver(resp)  # retransmitted 2xx -> dialog re-ACKs
            return
        if status < 200:
            self.state = "proceeding"
            if self.method == "INVITE" and self._timeout_h:
                # INVITE may ring indefinitely once a provisional arrives
                self._timeout_h.cancel()
                self._timeout_h = None
            self._deliver(resp)
            return
        self.state = "completed"
        self.final = resp
        self._stop_timers()
        if self.method == "INVITE" and status >= 300:
            self.ack = self._build_ack(resp)
            try:
                self.layer.send_msg(self.ack, self.addr)
            except Exception:  # noqa: BLE001
                pass
        linger = TIMER_B if (self.method == "INVITE" or not self.layer.reliable) else 0.5
        asyncio.get_running_loop().call_later(linger, self.layer._remove_client, self)
        self._deliver(resp)

    def _build_ack(self, resp: SipMessage) -> SipMessage:
        ack = SipMessage.request("ACK", self.msg.uri)
        ack.add("Via", self.msg.vias[0])
        for r in self.msg.get_all("Route"):
            ack.add("Route", r)
        ack.add("From", self.msg.get("From"))
        ack.add("To", resp.get("To"))
        ack.add("Call-ID", self.msg.call_id)
        ack.add("CSeq", f"{self.msg.cseq[0]} ACK")
        ack.add("Max-Forwards", "70")
        return ack


class ServerTransaction:
    def __init__(self, layer: "TransactionLayer", req: SipMessage, addr):
        self.layer = layer
        self.request = req
        self.addr = addr
        self.method = req.method
        self.key = (req.top_via.branch if req.top_via else None, req.method)
        self.last: SipMessage | None = None
        self.final = False
        self.acked = False
        self._rt_task = None

    def respond(self, resp: SipMessage):
        if self.final:
            log.debug("[%s] dropping extra response %s for completed transaction",
                      self.layer.name, resp.status)
            return
        self.last = resp
        try:
            self.layer.send_msg(resp, self.addr)
        except Exception as e:  # noqa: BLE001
            log.warning("[%s] failed to send response: %s", self.layer.name, e)
        if resp.status >= 200:
            self.final = True
            if self.method == "INVITE" and resp.status >= 300 and not self.layer.reliable:
                self._rt_task = asyncio.create_task(self._retransmit())
            asyncio.get_running_loop().call_later(TIMER_B, self.layer._remove_server, self)

    def reply(self, status: int, reason: str | None = None, to_tag: str | None = None,
              headers: list[tuple[str, str]] | None = None) -> SipMessage:
        resp = make_response(self.request, status, reason, to_tag)
        for k, v in headers or []:
            resp.add(k, v)
        self.layer.decorate_response(resp)
        self.respond(resp)
        return resp

    async def _retransmit(self):
        interval = T1
        try:
            while not self.acked:
                await asyncio.sleep(interval)
                if self.acked:
                    return
                self.layer.send_msg(self.last, self.addr)
                interval = min(interval * 2, T2)
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

    def on_retransmit(self):
        if self.last is not None:
            try:
                self.layer.send_msg(self.last, self.addr)
            except Exception:  # noqa: BLE001
                pass

    def on_ack(self):
        self.acked = True
        if self._rt_task:
            self._rt_task.cancel()
            self._rt_task = None


class TransactionLayer:
    def __init__(self, transport, request_handler, name: str = "", user_agent: str = ""):
        self.transport = transport
        self.request_handler = request_handler
        self.name = name or getattr(transport, "name", "")
        self.user_agent = user_agent
        self.client: dict = {}
        self.server: dict = {}

    @property
    def reliable(self) -> bool:
        return self.transport.reliable

    def send_msg(self, msg: SipMessage, addr):
        self.transport.send(msg.to_bytes(), addr)

    def decorate_response(self, resp: SipMessage):
        if self.user_agent and resp.get("Server") is None:
            resp.add("Server", self.user_agent)

    def make_via(self, branch: str) -> Via:
        host, port = self.transport.sent_by
        params = [["branch", branch], ["rport", None]]
        return Via(self.transport.proto, host, port, params)

    def send_request(self, msg: SipMessage, addr, callback, branch: str | None = None,
                     timeout: float | None = None) -> ClientTransaction:
        msg.remove("Via")
        msg.add("Via", self.make_via(branch or gen_branch()), top=True)
        msg.headers.sort(key=lambda h: 0 if h[0] == "Via" else 1)
        txn = ClientTransaction(self, msg, addr, callback, timeout)
        self.client[txn.key] = txn
        txn.start()
        return txn

    def send_ack(self, ack: SipMessage, addr, branch: str | None = None):
        """Send an ACK for a 2xx (its own transaction-less request)."""
        if not ack.get("Via"):
            ack.add("Via", self.make_via(branch or gen_branch()), top=True)
            ack.headers.sort(key=lambda h: 0 if h[0] == "Via" else 1)
        self.send_msg(ack, addr)

    def _remove_client(self, txn):
        if self.client.get(txn.key) is txn:
            del self.client[txn.key]

    def _remove_server(self, txn):
        if self.server.get(txn.key) is txn:
            del self.server[txn.key]

    def close(self):
        for txn in list(self.client.values()):
            txn._fail(503, "Connection Lost")
        self.client.clear()
        self.server.clear()

    def handle(self, msg: SipMessage, addr):
        if not msg.is_request:
            via = msg.top_via
            if via is None:
                return
            txn = self.client.get((via.branch, msg.cseq[1]))
            if txn is not None:
                txn.on_response(msg)
            else:
                log.debug("[%s] stray response %s", self.name, msg.summary())
            return

        via = msg.top_via
        if via is None:
            return
        if addr is not None and not self.transport.reliable:
            if via.host != addr[0]:
                via.set_param("received", addr[0])
            if via.param("rport") is not None:
                via.set_param("rport", str(addr[1]))
                via.set_param("received", addr[0])
            msg.set_top_via(via)
        branch = via.branch
        if msg.method == "ACK":
            st = self.server.get((branch, "INVITE"))
            if st is not None and st.last is not None and st.last.status >= 300:
                st.on_ack()
                return
            self.request_handler(msg, addr, None)
            return
        st = self.server.get((branch, msg.method))
        if st is not None:
            st.on_retransmit()
            return
        st = ServerTransaction(self, msg, addr)
        self.server[st.key] = st
        self.request_handler(msg, addr, st)
