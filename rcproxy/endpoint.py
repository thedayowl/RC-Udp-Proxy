"""Per-endpoint runtime: phone registration/reachability and RingCentral registration."""
from __future__ import annotations

import asyncio
import logging
import time

from .config import Endpoint
from .sip.digest import build_authorization
from .sip.message import NameAddr, SipMessage, SipUri, gen_callid, gen_tag, make_response
from .sip.transport import StreamConnection, TransactionLayer

log = logging.getLogger("rcproxy.endpoint")

ALLOW = "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, REFER, NOTIFY, MESSAGE"
OPTIONS_TIMEOUT = 4.0
RC_FIELDS = ("enabled", "rc_sip_domain", "rc_outbound_proxy", "rc_username", "rc_password",
             "rc_auth_id", "rc_transport")


class RegistrationError(Exception):
    pass


class AuthRequest:
    """Sends a request to RingCentral, transparently answering digest challenges."""

    def __init__(self, ep: "EndpointRuntime", msg: SipMessage, callback, cseq_alloc):
        self.ep = ep
        self.msg = msg
        self.callback = callback
        self.cseq_alloc = cseq_alloc
        self.attempts = 0
        self.txn = None

    def send(self):
        layer = self.ep.rc_layer
        if layer is None:
            resp = make_response(self.msg, 503, "No Connection To RingCentral")
            resp.synthetic = True
            asyncio.get_running_loop().call_soon(self.callback, resp)
            return self
        self.txn = layer.send_request(self.msg, None, self._on_response)
        return self

    def _on_response(self, resp: SipMessage):
        if resp.status in (401, 407) and self.attempts < 2 and not getattr(resp, "synthetic", False):
            hname = "WWW-Authenticate" if resp.status == 401 else "Proxy-Authenticate"
            chal = resp.get(hname)
            if chal and self.ep.rc_layer is not None:
                self.attempts += 1
                cfg = self.ep.reg_cfg or self.ep.cfg
                new = self.msg.copy()
                new.remove("Via")
                new.remove("Authorization")
                new.remove("Proxy-Authorization")
                try:
                    auth = build_authorization(chal, new.method, new.uri, cfg.rc_auth_id,
                                               cfg.rc_password)
                except ValueError as e:
                    log.warning("[%s] cannot answer challenge: %s", self.ep.label, e)
                    self.callback(resp)
                    return
                new.add("Authorization" if resp.status == 401 else "Proxy-Authorization", auth)
                new.set("CSeq", f"{self.cseq_alloc()} {new.method}")
                self.msg = new
                self.send()
                return
        self.callback(resp)


class EndpointRuntime:
    def __init__(self, core, cfg: Endpoint):
        self.core = core
        self.cfg = cfg
        self.reg_cfg: Endpoint | None = None   # config used for the active RC registration
        # phone side
        self.phone_contact: str | None = None
        self.phone_addr: tuple[str, int] | None = None
        self.phone_expires_at = 0.0
        self.phone_registered_at = 0.0
        self.phone_ua = ""
        self.options_failures = 0
        self.last_options_ok = 0.0
        self.last_options_rtt: float | None = None
        self.phone_offline_reason = "never registered"
        # RingCentral side
        self.rc_state = "idle"
        self.rc_error = ""
        self.rc_conn: StreamConnection | None = None
        self.rc_layer: TransactionLayer | None = None
        self.rc_expires_at = 0.0
        self.rc_refresh_at = 0.0
        self.rc_registered_at = 0.0
        self.rc_callid = gen_callid()
        self.rc_cseq = 0
        self.rc_from_tag = gen_tag()
        self.learned_public_ip: str | None = None
        self.calls: set = set()
        self._wake = asyncio.Event()
        self._waiters: list[asyncio.Future] = []
        self._reset = False
        self._stopped = False
        self._tasks: list[asyncio.Task] = []

    @property
    def label(self) -> str:
        return self.cfg.name or self.cfg.phone_username

    # ------------------------------------------------------------------ life
    def start(self):
        self._tasks = [asyncio.create_task(self._supervise()),
                       asyncio.create_task(self._phone_monitor())]

    async def stop(self):
        self._stopped = True
        self.set_phone_offline("endpoint removed", wake=False)
        for t in self._tasks:
            t.cancel()
        await self._teardown_rc()

    def apply_config(self, cfg: Endpoint):
        old = self.cfg
        self.cfg = cfg
        if (old.phone_username != cfg.phone_username or old.phone_password != cfg.phone_password
                or not cfg.enabled):
            self.set_phone_offline("configuration changed", wake=False)
        if any(getattr(old, f) != getattr(cfg, f) for f in RC_FIELDS):
            self._reset = True
        self._wake.set()

    # ------------------------------------------------------------ phone side
    @property
    def phone_online(self) -> bool:
        return self.phone_addr is not None and time.time() < self.phone_expires_at

    def on_phone_register(self, contact: str, addr, expires: int, ua: str):
        was_online = self.phone_online
        changed = addr != self.phone_addr or contact != self.phone_contact
        self.phone_contact = contact
        self.phone_addr = addr
        self.phone_expires_at = time.time() + expires
        self.phone_ua = ua
        if not was_online:
            self.phone_registered_at = time.time()
            self.options_failures = 0
            self.last_options_ok = time.time()
            log.info("[%s] phone registered from %s:%s (%s), expires %ss",
                     self.label, addr[0], addr[1], ua or "unknown UA", expires)
            self._wake.set()
        elif changed:
            log.info("[%s] phone contact changed to %s:%s", self.label, addr[0], addr[1])

    def set_phone_offline(self, reason: str, wake: bool = True):
        if self.phone_addr is None:
            return
        log.info("[%s] phone offline: %s", self.label, reason)
        self.phone_offline_reason = reason
        self.phone_addr = None
        self.phone_contact = None
        self.phone_expires_at = 0
        for call in list(self.calls):
            self.core.spawn(call.hangup(None, f"phone offline ({reason})"))
        if wake:
            self._wake.set()

    async def _phone_monitor(self):
        next_ping = 0.0
        while not self._stopped:
            await asyncio.sleep(1)
            if self.phone_addr is None:
                next_ping = 0.0
                continue
            now = time.time()
            if now >= self.phone_expires_at:
                self.set_phone_offline("registration expired")
                continue
            if next_ping == 0.0:
                next_ping = now + self.core.settings.options_interval
                continue
            if now < next_ping:
                continue
            next_ping = now + self.core.settings.options_interval
            ok = await self._ping_phone()
            if self.phone_addr is None:
                continue
            if ok:
                if self.options_failures:
                    log.info("[%s] phone answering OPTIONS again", self.label)
                self.options_failures = 0
            else:
                self.options_failures += 1
                log.warning("[%s] phone did not answer OPTIONS (%d/%d)", self.label,
                            self.options_failures, self.core.settings.options_max_failures)
                if self.options_failures >= self.core.settings.options_max_failures:
                    self.set_phone_offline("not responding to OPTIONS")

    async def _ping_phone(self) -> bool:
        lan = self.core.lan_ip
        m = SipMessage.request("OPTIONS", self.phone_contact)
        m.add("Max-Forwards", "70")
        m.add("From", f"<sip:rcproxy@{lan}>;tag={gen_tag()}")
        m.add("To", f"<sip:{self.cfg.phone_username}@{lan}>")
        m.add("Call-ID", gen_callid(lan))
        m.add("CSeq", "1 OPTIONS")
        m.add("Accept", "application/sdp")
        m.add("User-Agent", self.core.user_agent)
        fut = asyncio.get_running_loop().create_future()
        started = time.time()

        def cb(resp):
            if resp.status >= 200 and not fut.done():
                fut.set_result(resp)

        self.core.phone_layer.send_request(m, self.phone_addr, cb, timeout=OPTIONS_TIMEOUT)
        resp = await fut
        if getattr(resp, "synthetic", False):
            return False
        self.last_options_ok = time.time()
        self.last_options_rtt = time.time() - started
        return True

    # ------------------------------------------------------- RingCentral side
    def rc_contact(self) -> str:
        cfg = self.reg_cfg or self.cfg
        host, port = self.rc_conn.local if self.rc_conn else ("0.0.0.0", 0)
        return f"<sip:{cfg.rc_username}@{host}:{port};transport={cfg.rc_transport}>"

    def media_public_ip(self) -> str:
        s = self.core.settings
        if s.public_ip:
            return s.public_ip
        if self.learned_public_ip:
            return self.learned_public_ip
        if self.rc_conn and not self.rc_conn.closed:
            return self.rc_conn.local[0]
        return self.core.lan_ip

    def next_rc_cseq(self) -> int:
        self.rc_cseq += 1
        return self.rc_cseq

    def rc_send(self, msg: SipMessage, callback, cseq_alloc=None) -> AuthRequest:
        return AuthRequest(self, msg, callback, cseq_alloc or self.next_rc_cseq).send()

    async def rc_request(self, msg: SipMessage, cseq_alloc=None) -> SipMessage:
        fut = asyncio.get_running_loop().create_future()

        def cb(resp):
            if resp.status >= 200 and not fut.done():
                fut.set_result(resp)

        self.rc_send(msg, cb, cseq_alloc)
        return await fut

    async def wait_rc_registered(self, timeout: float) -> bool:
        if self.rc_state == "registered":
            return True
        fut = asyncio.get_running_loop().create_future()
        self._waiters.append(fut)
        self._wake.set()
        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout)
        except asyncio.TimeoutError:
            return False

    def _notify(self, ok: bool):
        waiters, self._waiters = self._waiters, []
        for f in waiters:
            if not f.done():
                f.set_result(ok)

    async def _supervise(self):
        backoff = 0
        retry_at = 0.0
        while not self._stopped:
            self._wake.clear()
            timeout = None
            try:
                if self._reset:
                    self._reset = False
                    await self._teardown_rc()
                want = self.cfg.enabled and self.phone_online
                if want:
                    now = time.time()
                    if self.rc_state != "registered" or now >= self.rc_refresh_at:
                        if now < retry_at and not self._waiters:
                            timeout = retry_at - now
                        else:
                            await self._register(self.core.settings.rc_register_expires)
                            backoff = 0
                            retry_at = 0.0
                            self._notify(True)
                    if self.rc_state == "registered":
                        timeout = max(1.0, self.rc_refresh_at - time.time())
                else:
                    self._notify(False)
                    if self.rc_conn is not None or self.rc_state not in ("idle",):
                        await self._teardown_rc()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                err = str(e) or type(e).__name__
                log.warning("[%s] RingCentral registration failed: %s", self.label, err)
                self._drop_connection(f"registration failed: {err}")
                self.rc_state = "error"
                self.rc_error = err
                backoff = min(max(backoff * 2, 5), 300)
                retry_at = time.time() + backoff
                timeout = backoff
                self._notify(False)
            try:
                await asyncio.wait_for(self._wake.wait(), timeout)
            except asyncio.TimeoutError:
                pass

    async def _ensure_connected(self):
        if self.rc_conn is not None and not self.rc_conn.closed:
            return
        cfg = self.cfg
        host, port = cfg.proxy_hostport()
        self.rc_state = "connecting"
        conn = StreamConnection(self.label, self._on_rc_message, self._on_rc_closed)
        await conn.open(host, port, tls=cfg.rc_transport == "tls",
                        verify=self.core.settings.tls_verify)
        self.rc_conn = conn
        self.rc_layer = TransactionLayer(conn, self._on_rc_request, self.label,
                                         self.core.user_agent)
        self.rc_callid = gen_callid()
        self.rc_from_tag = gen_tag()
        self.reg_cfg = cfg

    def _on_rc_message(self, msg, addr):
        if self.rc_layer is not None:
            self.rc_layer.handle(msg, addr)

    def _on_rc_request(self, msg, addr, stx):
        self.core.handle_rc_request(self, msg, stx)

    def _on_rc_closed(self, conn, reason):
        if conn is not self.rc_conn:
            return
        layer = self.rc_layer
        self.rc_conn = None
        self.rc_layer = None
        if layer is not None:
            layer.close()
        for call in list(self.calls):
            self.core.spawn(call.hangup(None, "RingCentral connection lost"))
        if self.rc_state in ("registered", "registering", "connecting"):
            self.rc_state = "disconnected"
            self.rc_error = f"connection {reason}"
        self._wake.set()

    def _drop_connection(self, reason: str):
        if self.rc_conn is not None:
            self.rc_conn.close()
        self.rc_conn = None
        self.rc_layer = None

    async def _teardown_rc(self):
        for call in list(self.calls):
            await call.hangup(None, "RingCentral registration removed")
        if self.rc_state == "registered" and self.rc_conn is not None and not self.rc_conn.closed:
            try:
                await asyncio.wait_for(self._register(0), 5)
            except Exception as e:  # noqa: BLE001
                log.info("[%s] unregister failed: %s", self.label, e)
        self._drop_connection("unregistered")
        if self.rc_state not in ("error", "disconnected"):
            self.rc_error = ""  # keep the last failure visible in the UI
        self.rc_state = "idle"
        self.rc_expires_at = self.rc_refresh_at = 0

    async def _register(self, expires: int, _retry423: bool = True):
        await self._ensure_connected()
        cfg = self.reg_cfg or self.cfg
        if expires and self.rc_state != "registered":
            self.rc_state = "registering"
        dom = cfg.rc_sip_domain
        m = SipMessage.request("REGISTER", f"sip:{dom}")
        m.add("Max-Forwards", "70")
        m.add("From", f"<sip:{cfg.rc_username}@{dom}>;tag={self.rc_from_tag}")
        m.add("To", f"<sip:{cfg.rc_username}@{dom}>")
        m.add("Call-ID", self.rc_callid)
        m.add("CSeq", f"{self.next_rc_cseq()} REGISTER")
        m.add("Contact", self.rc_contact())
        m.add("Expires", str(expires))
        m.add("Allow", ALLOW)
        m.add("User-Agent", self.core.user_agent)
        resp = await self.rc_request(m)
        if 200 <= resp.status < 300:
            via = resp.top_via
            if via is not None and via.param("received"):
                ip = via.param("received")
                if ip != self.learned_public_ip:
                    log.info("[%s] public address seen by RingCentral: %s", self.label, ip)
                self.learned_public_ip = ip
            if expires == 0:
                log.info("[%s] unregistered from RingCentral", self.label)
                self.rc_state = "idle"
                return
            granted = self._granted_expires(resp, expires)
            now = time.time()
            if self.rc_state != "registered":
                log.info("[%s] registered to RingCentral as %s (expires %ss)", self.label,
                         cfg.rc_username, granted)
                self.rc_registered_at = now
            self.rc_state = "registered"
            self.rc_error = ""
            self.rc_expires_at = now + granted
            self.rc_refresh_at = now + max(10, min(granted * 0.8, granted - 30))
            return
        if resp.status == 423 and _retry423:
            try:
                minexp = int(resp.get("Min-Expires", "0"))
            except ValueError:
                minexp = 0
            if minexp > expires:
                return await self._register(minexp, _retry423=False)
        raise RegistrationError(f"{resp.status} {resp.reason}")

    def _granted_expires(self, resp: SipMessage, requested: int) -> int:
        ours = SipUri.parse(NameAddr.parse(self.rc_contact()).uri)
        contacts = resp.get_list("Contact")
        for c in contacts:
            try:
                na = NameAddr.parse(c)
                u = SipUri.parse(na.uri)
            except ValueError:
                continue
            if (u.host == ours.host and u.port == ours.port) or len(contacts) == 1:
                if na.param("expires"):
                    try:
                        return max(1, int(na.param("expires")))
                    except ValueError:
                        pass
        return max(1, resp.expires_value(requested))

    # ---------------------------------------------------------------- status
    def status(self) -> dict:
        now = time.time()
        return {
            "phone": {
                "online": self.phone_online,
                "address": f"{self.phone_addr[0]}:{self.phone_addr[1]}" if self.phone_addr else None,
                "contact": self.phone_contact,
                "user_agent": self.phone_ua,
                "expires_in": int(self.phone_expires_at - now) if self.phone_online else None,
                "options_failures": self.options_failures,
                "last_options_ok": int(now - self.last_options_ok) if self.phone_online else None,
                "options_rtt_ms": round(self.last_options_rtt * 1000, 1)
                if self.last_options_rtt is not None and self.phone_online else None,
                "offline_reason": None if self.phone_online else self.phone_offline_reason,
            },
            "rc": {
                "state": self.rc_state,
                "error": self.rc_error,
                "expires_in": int(self.rc_expires_at - now) if self.rc_state == "registered" else None,
                "local": "%s:%s" % self.rc_conn.local if self.rc_conn else None,
                "remote": "%s:%s" % self.rc_conn.peer if self.rc_conn else None,
                "transport": self.rc_conn.proto if self.rc_conn else None,
                "public_ip": self.media_public_ip() if self.rc_conn else None,
            },
            "calls": len(self.calls),
        }
