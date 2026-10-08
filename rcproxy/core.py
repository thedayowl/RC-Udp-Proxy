"""Proxy core: phone-side UDP listener, request routing, endpoint management."""
from __future__ import annotations

import asyncio
import collections
import logging
import time
from urllib.parse import quote, unquote

from . import __version__
from .call import Call, Leg
from .config import ConfigStore, Endpoint, Settings, detect_lan_ip
from .endpoint import ALLOW, EndpointRuntime
from .media import PortAllocator
from .sip.digest import DigestServer
from .sip.message import NameAddr, SipMessage, SipUri, gen_callid, gen_tag
from .sip.transport import TransactionLayer, UdpTransport

log = logging.getLogger("rcproxy.core")


class Core:
    def __init__(self, store: ConfigStore):
        self.store = store
        self.user_agent = f"RC-UDP-Proxy/{__version__}"
        self.endpoints: dict[str, EndpointRuntime] = {}
        self.legs: dict[tuple[str, str], Leg] = {}
        self.calls: dict[str, Call] = {}
        self.history: collections.deque = collections.deque(maxlen=100)
        self.digest = DigestServer(self.settings.realm)
        self.ports = PortAllocator(self.settings.rtp_port_min, self.settings.rtp_port_max)
        self.lan_ip = self.settings.lan_ip or detect_lan_ip()
        self.phone_udp: UdpTransport | None = None
        self.phone_layer: TransactionLayer | None = None
        self._udp_transport = None
        self._tasks: set[asyncio.Task] = set()

    @property
    def settings(self) -> Settings:
        return self.store.settings

    # ------------------------------------------------------------- lifecycle
    async def start(self):
        await self._bind_udp()
        for cfg in self.store.endpoints:
            self._start_endpoint(cfg)
        log.info("SIP listening on UDP %s:%s (advertised as %s); RTP ports %s-%s",
                 "0.0.0.0", self.settings.sip_port, self.lan_ip, self.settings.rtp_port_min,
                 self.settings.rtp_port_max)

    async def _bind_udp(self):
        if self._udp_transport is not None:
            self._udp_transport.close()
        loop = asyncio.get_running_loop()
        self.phone_udp = UdpTransport(self._on_phone_message,
                                      lambda: (self.lan_ip, self.settings.sip_port))
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: self.phone_udp, local_addr=("0.0.0.0", self.settings.sip_port))
        self.phone_layer = TransactionLayer(self.phone_udp, self._on_phone_request, "phones",
                                            self.user_agent)

    async def stop(self):
        for ep in list(self.endpoints.values()):
            await ep.stop()
        if self._udp_transport is not None:
            self._udp_transport.close()

    def spawn(self, coro) -> asyncio.Task:
        t = asyncio.create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._task_done)
        return t

    def _task_done(self, t: asyncio.Task):
        self._tasks.discard(t)
        if not t.cancelled() and t.exception() is not None:
            log.error("background task failed", exc_info=t.exception())

    def _start_endpoint(self, cfg: Endpoint):
        rt = EndpointRuntime(self, cfg)
        self.endpoints[cfg.id] = rt
        rt.start()

    # ---------------------------------------------------- config management
    async def add_endpoint(self, cfg: Endpoint):
        self.store.endpoints.append(cfg)
        self.store.save()
        self._start_endpoint(cfg)

    async def update_endpoint(self, cfg: Endpoint):
        self.store.endpoints = [cfg if e.id == cfg.id else e for e in self.store.endpoints]
        self.store.save()
        rt = self.endpoints.get(cfg.id)
        if rt is not None:
            rt.apply_config(cfg)
        else:
            self._start_endpoint(cfg)

    async def delete_endpoint(self, ep_id: str):
        self.store.endpoints = [e for e in self.store.endpoints if e.id != ep_id]
        self.store.save()
        rt = self.endpoints.pop(ep_id, None)
        if rt is not None:
            await rt.stop()

    async def reregister(self, ep_id: str):
        rt = self.endpoints.get(ep_id)
        if rt is not None:
            rt._reset = True
            rt._wake.set()

    async def update_settings(self, new: Settings):
        old = self.store.settings
        self.store.settings = new
        self.store.save()
        if new.realm != old.realm:
            self.digest = DigestServer(new.realm)
        if (new.rtp_port_min, new.rtp_port_max) != (old.rtp_port_min, old.rtp_port_max):
            used = self.ports.used
            self.ports = PortAllocator(new.rtp_port_min, new.rtp_port_max)
            self.ports.used = used
        self.lan_ip = new.lan_ip or detect_lan_ip()
        if new.sip_port != old.sip_port:
            await self._bind_udp()
            log.info("SIP now listening on UDP port %s", new.sip_port)
        from .logsetup import apply_levels
        apply_levels(new)

    # -------------------------------------------------------- registries
    def register_leg(self, leg: Leg):
        self.legs[(leg.side, leg.call_id)] = leg

    def register_call(self, call: Call):
        self.calls[call.id] = call

    def unregister_call(self, call: Call):
        self.calls.pop(call.id, None)
        for leg in (call.phone, call.rc):
            if self.legs.get((leg.side, leg.call_id)) is leg:
                del self.legs[(leg.side, leg.call_id)]
        self.history.appendleft(call.status())

    def by_phone_user(self, user: str | None) -> EndpointRuntime | None:
        if not user:
            return None
        for rt in self.endpoints.values():
            if rt.cfg.phone_username == user:
                return rt
        return None

    # ------------------------------------------------------- phone side
    def _on_phone_message(self, msg: SipMessage, addr):
        self.phone_layer.handle(msg, addr)

    def _on_phone_request(self, req: SipMessage, addr, stx):
        m = req.method
        if m == "REGISTER":
            self.spawn(self._phone_register(req, addr, stx))
            return
        if req.to_tag or m == "ACK":
            leg = self.legs.get(("phone", req.call_id))
            if leg is not None and (m == "ACK" or req.to_tag == leg.local_tag):
                leg.call.dispatch(leg, req, stx)
            elif stx is not None:
                stx.reply(481)
            return
        if m == "CANCEL":
            leg = self.legs.get(("phone", req.call_id))
            if leg is not None and leg is leg.call.a:
                leg.call.spawn(leg.call.on_cancel(stx))
            else:
                stx.reply(481)
            return
        if m == "INVITE":
            self.spawn(self._phone_invite(req, addr, stx))
        elif m == "OPTIONS":
            stx.reply(200, headers=[("Allow", ALLOW), ("Accept", "application/sdp")])
        elif m in ("SUBSCRIBE", "PUBLISH"):
            stx.reply(489)
        elif m == "NOTIFY":
            stx.reply(200)
        else:
            stx.reply(405, headers=[("Allow", ALLOW)])

    def _authenticate(self, req: SipMessage, stx, ep: EndpointRuntime | None, proxy: bool) -> bool:
        hdr = req.get("Proxy-Authorization") or req.get("Authorization")

        def lookup(user):
            if ep is not None and user == ep.cfg.phone_username:
                return ep.cfg.phone_password
            return None

        result, _ = self.digest.verify(hdr, req.method, lookup)
        if result == "ok":
            return True
        if result in ("missing", "stale"):
            name = "Proxy-Authenticate" if proxy else "WWW-Authenticate"
            stx.reply(407 if proxy else 401,
                      headers=[(name, self.digest.challenge(stale=result == "stale"))])
        else:
            log.warning("authentication failed for %s from %s:%s",
                        req.from_hdr.uri, stx.addr[0], stx.addr[1])
            stx.reply(403)
        return False

    async def _phone_register(self, req: SipMessage, addr, stx):
        try:
            user = SipUri.parse(req.to_hdr.uri).user
        except ValueError:
            stx.reply(400)
            return
        ep = self.by_phone_user(user)
        if not self._authenticate(req, stx, ep, proxy=False):
            return
        if not ep.cfg.enabled:
            stx.reply(403, "Endpoint Disabled")
            return
        s = self.settings
        contacts = req.get_list("Contact")
        req_exp = req.expires_value(None)
        if not contacts:
            hdrs = []
            if ep.phone_online:
                remaining = int(ep.phone_expires_at - time.time())
                hdrs.append(("Contact", f"<{ep.phone_contact}>;expires={remaining}"))
            stx.reply(200, headers=hdrs)
            return
        if contacts[0].strip() == "*":
            ep.set_phone_offline("phone unregistered")
            stx.reply(200)
            return
        na = NameAddr.parse(contacts[0])
        exp = na.param("expires")
        try:
            expires = int(exp) if exp is not None else (req_exp if req_exp is not None else 3600)
        except ValueError:
            expires = 3600
        if expires == 0:
            ep.set_phone_offline("phone unregistered")
            stx.reply(200)
            return
        if expires < s.phone_min_expires:
            stx.reply(423, headers=[("Min-Expires", str(s.phone_min_expires))])
            return
        expires = min(expires, s.phone_max_expires)
        ep.on_phone_register(na.uri, addr, expires, req.get("User-Agent", ""))
        if ep.rc_state != "registered":
            ok = await ep.wait_rc_registered(15)
            if not ok:
                reason = ep.rc_error or "RingCentral registration pending"
                log.warning("[%s] rejecting phone registration: %s", ep.label, reason)
                ep.set_phone_offline(f"RingCentral registration failed ({reason})")
                stx.reply(503, "RingCentral Registration Failed",
                          headers=[("Retry-After", "30"), ("Warning", f'399 rcproxy "{reason}"')])
                return
        stx.reply(200, headers=[("Contact", f"<{na.uri}>;expires={expires}"),
                                ("Expires", str(expires))])

    async def _phone_invite(self, req: SipMessage, addr, stx):
        try:
            user = SipUri.parse(req.from_hdr.uri).user
        except ValueError:
            stx.reply(400)
            return
        ep = self.by_phone_user(user)
        if not self._authenticate(req, stx, ep, proxy=True):
            return
        if not ep.cfg.enabled:
            stx.reply(403, "Endpoint Disabled")
            return
        if ep.rc_state != "registered" or ep.rc_layer is None:
            stx.reply(503, "Not Registered To RingCentral")
            return
        call = Call(self, ep, "outbound")
        call.spawn(call.start(req, addr, stx))

    # ----------------------------------------------------- RingCentral side
    def handle_rc_request(self, ep: EndpointRuntime, req: SipMessage, stx):
        m = req.method
        if req.to_tag or m == "ACK":
            leg = self.legs.get(("rc", req.call_id))
            if leg is not None and leg.call.ep is ep and (m == "ACK" or req.to_tag == leg.local_tag):
                leg.call.dispatch(leg, req, stx)
            elif stx is not None:
                stx.reply(481)
            return
        if m == "CANCEL":
            leg = self.legs.get(("rc", req.call_id))
            if leg is not None and leg is leg.call.a:
                leg.call.spawn(leg.call.on_cancel(stx))
            else:
                stx.reply(481)
            return
        if m == "INVITE":
            call = Call(self, ep, "inbound")
            call.spawn(call.start(req, None, stx))
        elif m == "OPTIONS":
            stx.reply(200, headers=[("Allow", ALLOW), ("Accept", "application/sdp")])
        elif m == "NOTIFY":
            stx.reply(200)
            self._relay_notify_to_phone(ep, req)
        elif m == "MESSAGE":
            stx.reply(200)
        else:
            stx.reply(405, headers=[("Allow", ALLOW)])

    def _relay_notify_to_phone(self, ep: EndpointRuntime, req: SipMessage):
        """Forward unsolicited NOTIFY (e.g. voicemail MWI) to the phone."""
        if not ep.phone_online or not req.get("Event"):
            return
        lan = self.lan_ip
        user = ep.cfg.phone_username
        n = SipMessage.request("NOTIFY", ep.phone_contact)
        n.add("Max-Forwards", "70")
        n.add("From", f"<sip:{user}@{lan}>;tag={gen_tag()}")
        n.add("To", f"<sip:{user}@{lan}>")
        n.add("Call-ID", gen_callid(lan))
        n.add("CSeq", "1 NOTIFY")
        n.add("Contact", f"<sip:rcproxy@{lan}:{self.settings.sip_port}>")
        n.add("Event", req.get("Event"))
        n.add("Subscription-State", req.get("Subscription-State") or "active")
        n.add("User-Agent", self.user_agent)
        if req.body:
            n.add("Content-Type", req.get("Content-Type") or "application/simple-message-summary")
            n.body = req.body
        self.phone_layer.send_request(n, ep.phone_addr, lambda r: None)

    # ------------------------------------------------------------ transfer
    def translate_refer_to(self, value: str, from_leg: Leg, to_leg: Leg, call: Call) -> str:
        try:
            na = NameAddr.parse(value)
            uri = SipUri.parse(na.uri)
        except ValueError:
            return value
        if uri.scheme == "tel":
            return value
        if to_leg.side == "rc":
            uri.host = call.ep.cfg.rc_sip_domain
            uri.port = None
        else:
            uri.host = self.lan_ip
            uri.port = self.settings.sip_port
        uri.del_param("transport")
        if uri.headers:
            parts = []
            for h in uri.headers.split("&"):
                k, _, v = h.partition("=")
                if k.lower() == "replaces":
                    v = self._translate_replaces(unquote(v), from_leg.side)
                    if v is None:
                        continue
                    v = quote(v, safe="")
                parts.append(f"{k}={v}")
            uri.headers = "&".join(parts)
        na.uri = str(uri)
        return str(na)

    def _translate_replaces(self, value: str, side: str) -> str | None:
        callid, _, params = value.partition(";")
        leg = self.legs.get((side, callid))
        if leg is None:
            return None
        target = leg.call.other(leg)
        return f"{target.call_id};to-tag={target.remote_tag};from-tag={target.local_tag}"

    # -------------------------------------------------------------- status
    def status(self) -> dict:
        return {
            "version": __version__,
            "lan_ip": self.lan_ip,
            "sip_port": self.settings.sip_port,
            "endpoints": {eid: rt.status() for eid, rt in self.endpoints.items()},
            "calls": [c.status() for c in self.calls.values()],
            "history": list(self.history)[:50],
            "default_password": self.store.using_default_password(),
        }
