"""Back-to-back user agent: bridges a phone-side dialog with a RingCentral-side dialog."""
from __future__ import annotations

import asyncio
import logging
import random
import secrets
import time

from .endpoint import ALLOW
from .media import MediaSession
from .sip.message import NameAddr, SipMessage, SipUri, gen_callid, gen_tag, make_response
from .sip.transport import T1, T2, TIMER_B

log = logging.getLogger("rcproxy.call")

RELAY_REQ_HEADERS = ("Event", "Subscription-State", "Reason", "Content-Disposition",
                     "Accept", "Expires", "Subject")
RELAY_RESP_HEADERS = ("Event", "Reason", "Warning", "Retry-After", "Content-Disposition",
                      "Accept", "Expires", "Min-Expires", "Unsupported")
DIALOG_METHODS = ("INVITE", "UPDATE", "SUBSCRIBE", "REFER", "NOTIFY")


class Leg:
    def __init__(self, call: "Call", side: str):
        self.call = call
        self.side = side              # "phone" or "rc"
        self.call_id: str | None = None
        self.local_tag = gen_tag()
        self.remote_tag: str | None = None
        self.local_uri = ""
        self.remote_uri = ""
        self.local_cseq = random.randint(1, 500)
        self.remote_cseq: int | None = None
        self.remote_target: str | None = None
        self.route_set: list[str] = []
        self.addr = None
        self.confirmed = False
        self.invite_stx = None        # UAS: server transaction of the initial INVITE
        self.invite_ctx = None        # UAC: AuthRequest / ClientTransaction of initial INVITE
        self.last_ack: SipMessage | None = None
        self.acked_cseq = 0
        self._2xx_task: asyncio.Task | None = None

    @property
    def layer(self):
        return self.call.core.phone_layer if self.side == "phone" else self.call.ep.rc_layer

    @property
    def contact(self) -> str:
        if self.side == "phone":
            return f"<sip:rcproxy@{self.call.core.lan_ip}:{self.call.core.settings.sip_port}>"
        return self.call.ep.rc_contact()

    def init_uas(self, req: SipMessage, addr):
        self.call_id = req.call_id
        self.remote_tag = req.from_tag
        f = req.from_hdr
        f.del_param("tag")
        self.remote_uri = str(f)
        t = req.to_hdr
        t.del_param("tag")
        self.local_uri = str(t)
        self.remote_cseq = req.cseq[0]
        contacts = req.get_list("Contact")
        self.remote_target = NameAddr.parse(contacts[0]).uri if contacts else f.uri
        self.route_set = req.get_list("Record-Route")
        self.addr = addr

    def update_from_response(self, resp: SipMessage):
        if resp.to_tag:
            self.remote_tag = resp.to_tag
        contacts = resp.get_list("Contact")
        if contacts:
            try:
                self.remote_target = NameAddr.parse(contacts[0]).uri
            except ValueError:
                pass
        if not self.confirmed:
            rr = resp.get_list("Record-Route")
            if rr:
                self.route_set = list(reversed(rr))

    def alloc_cseq(self) -> int:
        self.local_cseq += 1
        return self.local_cseq

    def new_request(self, method: str, cseq: int | None = None) -> SipMessage:
        m = SipMessage.request(method, self.remote_target)
        m.add("Max-Forwards", "70")
        for r in self.route_set:
            m.add("Route", r)
        m.add("From", f"{self.local_uri};tag={self.local_tag}")
        m.add("To", self.remote_uri + (f";tag={self.remote_tag}" if self.remote_tag else ""))
        m.add("Call-ID", self.call_id)
        if cseq is None:
            cseq = self.alloc_cseq()
        m.add("CSeq", f"{cseq} {method}")
        if method in DIALOG_METHODS:
            m.add("Contact", self.contact)
        m.add("User-Agent", self.call.core.user_agent)
        return m

    def send_request(self, msg: SipMessage, callback):
        if self.side == "rc":
            return self.call.ep.rc_send(msg, callback, self.alloc_cseq)
        return self.call.core.phone_layer.send_request(msg, self.addr, callback)

    def send_ack(self, cseq: int, body: bytes = b"", ctype: str | None = None):
        ack = self.new_request("ACK", cseq=cseq)
        if body:
            ack.add("Content-Type", ctype or "application/sdp")
            ack.body = body
        self.last_ack = ack
        layer = self.layer
        if layer is not None:
            try:
                layer.send_ack(ack, self.addr)
            except Exception as e:  # noqa: BLE001
                log.debug("ACK send failed: %s", e)

    def resend_ack(self):
        layer = self.layer
        if self.last_ack is not None and layer is not None:
            try:
                layer.send_msg(self.last_ack, self.addr)
            except Exception:  # noqa: BLE001
                pass

    def build_response(self, req: SipMessage, status: int, reason: str | None = None,
                       src: SipMessage | None = None, body: bytes = b"",
                       ctype: str | None = None) -> SipMessage:
        resp = make_response(req, status, reason, to_tag=self.local_tag)
        if 100 < status < 300 and req.method in DIALOG_METHODS:
            resp.add("Contact", self.contact)
        if src is not None:
            for h in RELAY_RESP_HEADERS:
                for v in src.get_all(h):
                    resp.add(h, v)
        if req.method == "INVITE" and 200 <= status < 300:
            resp.add("Allow", ALLOW)
        if body:
            resp.add("Content-Type", ctype or "application/sdp")
            resp.body = body
        resp.add("Server", self.call.core.user_agent)
        return resp

    def respond(self, stx, status: int, reason: str | None = None, src: SipMessage | None = None,
                body: bytes = b"", ctype: str | None = None):
        if stx is None or stx.final:
            return
        resp = self.build_response(stx.request, status, reason, src, body, ctype)
        stx.respond(resp)
        if stx.method == "INVITE" and 200 <= status < 300:
            self.confirmed = True
            if self.layer is not None and not self.layer.reliable:
                cseq = stx.request.cseq[0]
                self._2xx_task = asyncio.create_task(self._retransmit_2xx(resp, cseq))

    async def _retransmit_2xx(self, resp: SipMessage, cseq: int):
        interval = T1
        deadline = time.time() + TIMER_B
        try:
            while self.acked_cseq < cseq:
                await asyncio.sleep(interval)
                if self.acked_cseq >= cseq or self.call.state == "ended":
                    return
                if time.time() > deadline:
                    log.warning("[%s] no ACK from %s for 2xx, hanging up", self.call.ep.label,
                                self.side)
                    await self.call.hangup(None, f"no ACK from {self.side}")
                    return
                self.layer.send_msg(resp, self.addr)
                interval = min(interval * 2, T2)
        except asyncio.CancelledError:
            pass

    def got_ack(self, cseq: int):
        self.acked_cseq = max(self.acked_cseq, cseq)

    def stop(self):
        if self._2xx_task:
            self._2xx_task.cancel()
            self._2xx_task = None


class Call:
    def __init__(self, core, ep, direction: str):
        self.id = secrets.token_hex(4)
        self.core = core
        self.ep = ep
        self.direction = direction    # "outbound" (phone -> RC) or "inbound" (RC -> phone)
        self.phone = Leg(self, "phone")
        self.rc = Leg(self, "rc")
        if direction == "outbound":
            self.a, self.b = self.phone, self.rc
        else:
            self.a, self.b = self.rc, self.phone
        self.media = MediaSession(core, ep, ep.phone_addr[0] if ep.phone_addr else None)
        self.state = "init"
        self.created = time.time()
        self.answered_at: float | None = None
        self.ended_at: float | None = None
        self.end_reason = ""
        self.caller = ""
        self.callee = ""
        self.cancelled = False
        self.b_invite_has_sdp = False
        self.pending_ack: tuple[Leg, int] | None = None
        self._lock = asyncio.Lock()

    def other(self, leg: Leg) -> Leg:
        return self.rc if leg is self.phone else self.phone

    def spawn(self, coro):
        async def run():
            async with self._lock:
                try:
                    await coro
                except Exception:  # noqa: BLE001
                    log.exception("[%s] call %s error", self.ep.label, self.id)
                    await self.hangup(None, "internal error")
        return self.core.spawn(run())

    # ------------------------------------------------------------ setup
    async def start(self, req: SipMessage, addr, stx):
        a, b = self.a, self.b
        a.init_uas(req, addr)
        a.invite_stx = stx
        stx.reply(100)
        self.ep.calls.add(self)
        self.core.register_call(self)
        self.core.register_leg(a)
        cfg = self.ep.cfg
        lan = self.core.lan_ip
        if self.direction == "outbound":
            try:
                target = SipUri.parse(req.uri).user or req.to_hdr.sip_uri.user or ""
            except ValueError:
                target = ""
            if not target:
                a.respond(stx, 404, "No Number Dialed")
                await self.end("no number")
                return
            dom = cfg.rc_sip_domain
            b.call_id = gen_callid()
            b.local_uri = f"<sip:{cfg.rc_username}@{dom}>"
            b.remote_uri = f"<sip:{target}@{dom}>"
            b.remote_target = f"sip:{target}@{dom}"
            self.caller, self.callee = cfg.phone_username, target
        else:
            if not self.ep.phone_online:
                a.respond(stx, 480, "Phone Not Registered")
                await self.end("phone offline")
                return
            f = req.from_hdr
            pai = req.get("P-Asserted-Identity")
            ident = NameAddr.parse(pai) if pai else f
            try:
                caller = SipUri.parse(ident.uri).user or "anonymous"
            except ValueError:
                caller = "anonymous"
            display = ident.display or f.display
            b.call_id = gen_callid(lan)
            b.local_uri = (f"{display} " if display else "") + f"<sip:{caller}@{lan}>"
            b.remote_uri = f"<sip:{cfg.phone_username}@{lan}>"
            b.remote_target = self.ep.phone_contact
            b.addr = self.ep.phone_addr
            self.caller = (f"{f.display_name} " if f.display_name else "") + caller
            self.callee = cfg.phone_username
        self.core.register_leg(b)
        log.info("[%s] %s call %s: %s -> %s", self.ep.label, self.direction, self.id,
                 self.caller, self.callee)

        inv = b.new_request("INVITE")
        inv.add("Allow", ALLOW)
        if self.direction == "inbound":
            for h in ("Alert-Info", "Call-Info"):
                for v in req.get_all(h):
                    inv.add(h, v)
        if req.has_sdp:
            inv.body = await self.media.rewrite(req.body, a.side, b.side, True)
            inv.add("Content-Type", "application/sdp")
            self.b_invite_has_sdp = True
        self.state = "calling"
        b.invite_ctx = b.send_request(inv, lambda r: self.spawn(self._on_b_invite_response(r)))

    def _b_invite_msg(self) -> SipMessage | None:
        ctx = self.b.invite_ctx
        return getattr(ctx, "msg", None)

    async def _on_b_invite_response(self, resp: SipMessage):
        a, b = self.a, self.b
        st = resp.status
        if self.state == "ended":
            if 200 <= st < 300 and not b.confirmed:
                # answered after we gave up (e.g. CANCEL race): ACK then BYE
                b.update_from_response(resp)
                b.confirmed = True
                b.send_ack(resp.cseq[0])
                b.send_request(b.new_request("BYE"), lambda r: None)
            elif 200 <= st < 300:
                b.resend_ack()
            return
        if st == 100:
            return
        body = b""
        if resp.has_sdp:
            body = await self.media.rewrite(resp.body, b.side, a.side, not self.b_invite_has_sdp)
        if st < 200:
            b.update_from_response(resp)
            a.respond(a.invite_stx, st, resp.reason, src=resp, body=body)
            if self.state == "calling":
                self.state = "early"
            return
        if st < 300:
            if b.confirmed:
                b.resend_ack()
                return
            b.update_from_response(resp)
            b.confirmed = True
            if self.b_invite_has_sdp or not resp.has_sdp:
                b.send_ack(resp.cseq[0])
            else:
                self.pending_ack = (b, resp.cseq[0])
            if self.cancelled:
                await self.hangup(None, "cancelled")
                return
            a.respond(a.invite_stx, 200, resp.reason, src=resp, body=body)
            self.state = "confirmed"
            self.answered_at = time.time()
            log.info("[%s] call %s answered (%s)", self.ep.label, self.id,
                     "SRTP" if self.media.srtp else "RTP")
            return
        # failure
        if not self.cancelled:
            code = st if st not in (401, 407) else 403
            a.respond(a.invite_stx, code, resp.reason, src=resp)
        await self.end(f"{st} {resp.reason}")

    # ---------------------------------------------------------- requests
    def dispatch(self, leg: Leg, req: SipMessage, stx):
        if req.method == "ACK":
            self.spawn(self._on_ack(leg, req))
        else:
            self.spawn(self._on_request(leg, req, stx))

    async def _on_ack(self, leg: Leg, req: SipMessage):
        cseq = req.cseq[0]
        leg.got_ack(cseq)
        if leg._2xx_task and leg.acked_cseq >= cseq:
            leg.stop()
        if self.pending_ack is not None:
            other, ocseq = self.pending_ack
            if other is self.other(leg):
                self.pending_ack = None
                body = b""
                if req.has_sdp:
                    body = await self.media.rewrite(req.body, leg.side, other.side, False)
                other.send_ack(ocseq, body)

    async def on_cancel(self, stx):
        stx.reply(200)
        if self.state == "ended" or self.a.confirmed:
            return
        log.info("[%s] call %s cancelled by %s", self.ep.label, self.id, self.a.side)
        self.cancelled = True
        self.a.respond(self.a.invite_stx, 487)
        self._send_cancel()
        await self.end("cancelled")

    def _send_cancel(self):
        b = self.b
        inv = self._b_invite_msg()
        if inv is None or b.confirmed or b.layer is None:
            return
        c = SipMessage.request("CANCEL", inv.uri)
        c.add("Max-Forwards", "70")
        for r in inv.get_all("Route"):
            c.add("Route", r)
        c.add("From", inv.get("From"))
        c.add("To", inv.get("To"))
        c.add("Call-ID", inv.call_id)
        c.add("CSeq", f"{inv.cseq[0]} CANCEL")
        c.add("User-Agent", self.core.user_agent)
        try:
            b.layer.send_request(c, b.addr, lambda r: None, branch=inv.top_via.branch)
        except Exception as e:  # noqa: BLE001
            log.debug("CANCEL send failed: %s", e)

    async def _on_request(self, leg: Leg, req: SipMessage, stx):
        m = req.method
        if self.state == "ended":
            stx.reply(481)
            return
        if leg.remote_cseq is not None and req.cseq[0] < leg.remote_cseq:
            stx.reply(500, "CSeq Out Of Order")
            return
        leg.remote_cseq = req.cseq[0]
        if m == "BYE":
            stx.reply(200)
            await self.hangup(leg, f"BYE from {leg.side}")
            return
        other = self.other(leg)
        if not other.confirmed or other.layer is None:
            stx.reply(491 if m in ("INVITE", "UPDATE") else 481)
            return
        if m == "INVITE" and leg.layer is not None and not leg.layer.reliable:
            stx.reply(100)
        if m == "INVITE":
            contacts = req.get_list("Contact")
            if contacts:
                leg.remote_target = NameAddr.parse(contacts[0]).uri
        out = other.new_request(m)
        for h in RELAY_REQ_HEADERS:
            for v in req.get_all(h):
                out.add(h, v)
        if m == "INVITE":
            out.add("Allow", ALLOW)
        if m == "REFER":
            rt = req.get("Refer-To")
            if rt:
                out.add("Refer-To", self.core.translate_refer_to(rt, leg, other, self))
        if req.has_sdp:
            out.body = await self.media.rewrite(req.body, leg.side, other.side,
                                                m in ("INVITE", "UPDATE"))
            out.add("Content-Type", "application/sdp")
        elif req.body:
            out.body = req.body
            out.add("Content-Type", req.get("Content-Type") or "application/octet-stream")
        other.send_request(out, lambda r: self.spawn(self._on_relay_response(leg, stx, other, out, r)))

    async def _on_relay_response(self, leg: Leg, stx, other: Leg, out: SipMessage, resp: SipMessage):
        st = resp.status
        if st == 100:
            return
        is_inv = stx.method == "INVITE"
        if stx.final:
            if is_inv and 200 <= st < 300:
                other.resend_ack()
            return
        if self.state == "ended":
            if is_inv and 200 <= st < 300:
                other.send_ack(resp.cseq[0])
            return
        body, ctype = b"", None
        if resp.has_sdp:
            body = await self.media.rewrite(resp.body, other.side, leg.side, not out.has_sdp)
        elif resp.body:
            body, ctype = resp.body, resp.get("Content-Type")
        if is_inv and 200 <= st < 300:
            contacts = resp.get_list("Contact")
            if contacts:
                other.remote_target = NameAddr.parse(contacts[0]).uri
            if out.has_sdp or not resp.has_sdp:
                other.send_ack(resp.cseq[0])
            else:
                self.pending_ack = (other, resp.cseq[0])
        code = 500 if st in (401, 407) else st
        leg.respond(stx, code, resp.reason, src=resp, body=body, ctype=ctype)
        if st == 481 or (st == 408 and getattr(resp, "synthetic", False) and is_inv):
            await self.hangup(None, f"{other.side} dialog lost ({st})")

    # ---------------------------------------------------------- teardown
    async def hangup(self, origin: Leg | None, reason: str):
        if self.state == "ended":
            return
        for leg in (self.a, self.b):
            if leg is origin:
                continue
            if leg.confirmed and leg.layer is not None:
                try:
                    leg.send_request(leg.new_request("BYE"), lambda r: None)
                except Exception as e:  # noqa: BLE001
                    log.debug("BYE send failed: %s", e)
            elif leg is self.b and not self.cancelled:
                self.cancelled = True
                self._send_cancel()
            elif leg is self.a and leg.invite_stx is not None and not leg.invite_stx.final:
                leg.respond(leg.invite_stx, 487 if origin is None else 480)
        await self.end(reason)

    async def end(self, reason: str):
        if self.state == "ended":
            return
        self.state = "ended"
        self.ended_at = time.time()
        self.end_reason = reason
        self.phone.stop()
        self.rc.stop()
        self.media.close()
        self.ep.calls.discard(self)
        self.core.unregister_call(self)
        log.info("[%s] call %s ended: %s", self.ep.label, self.id, reason)

    def status(self) -> dict:
        now = time.time()
        return {
            "id": self.id,
            "endpoint": self.ep.label,
            "endpoint_id": self.ep.cfg.id,
            "direction": self.direction,
            "caller": self.caller,
            "callee": self.callee,
            "state": self.state,
            "started": self.created,
            "duration": int((self.ended_at or now) - self.answered_at) if self.answered_at else 0,
            "end_reason": self.end_reason,
            "srtp": self.media.srtp,
            "media": self.media.stats(),
        }
