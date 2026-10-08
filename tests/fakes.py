"""Test doubles: a UDP SIP phone and a RingCentral-like TCP/TLS SIP server."""
from __future__ import annotations

import asyncio
import base64
import secrets
import ssl

import pylibsrtp

from rcproxy.sip.digest import build_authorization, compute_response, parse_challenge
from rcproxy.sip.message import (SipMessage, StreamParser, Via, gen_branch, gen_callid, gen_tag,
                                 make_response, parse_message)
from rcproxy.sip.sdp import Sdp


def sdp_body(ip: str, port: int, extra: list[str] | None = None, proto="RTP/AVP") -> bytes:
    lines = ["v=0", f"o=test 1 1 IN IP4 {ip}", "s=test", f"c=IN IP4 {ip}", "t=0 0",
             f"m=audio {port} {proto} 0 101", "a=rtpmap:0 PCMU/8000",
             "a=rtpmap:101 telephone-event/8000", "a=sendrecv"]
    lines += extra or []
    return ("\r\n".join(lines) + "\r\n").encode()


def rtp_packet(seq: int, ssrc: int = 0x1234, payload: bytes = b"\xff" * 160) -> bytes:
    return bytes([0x80, 0x00]) + seq.to_bytes(2, "big") + (seq * 160).to_bytes(4, "big") + \
        ssrc.to_bytes(4, "big") + payload


class Media(asyncio.DatagramProtocol):
    def __init__(self):
        self.q: asyncio.Queue = asyncio.Queue()
        self.transport = None
        self.port = 0

    @classmethod
    async def open(cls):
        m = cls()
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(lambda: m, local_addr=("127.0.0.1", 0))
        m.port = m.transport.get_extra_info("sockname")[1]
        return m

    def connection_made(self, t):
        self.transport = t

    def datagram_received(self, data, addr):
        self.q.put_nowait((data, addr))

    def send(self, data, addr):
        self.transport.sendto(data, addr)

    async def recv(self, timeout=3.0):
        return await asyncio.wait_for(self.q.get(), timeout)

    def close(self):
        self.transport.close()


def sdp_target(body: bytes) -> tuple[str, int]:
    s = Sdp.parse(body)
    return s.media_connection(s.media[0]), s.media[0].port


class MsgQueue:
    def __init__(self):
        self.items: list[SipMessage] = []
        self.event = asyncio.Event()

    def put(self, m):
        self.items.append(m)
        self.event.set()

    async def get(self, pred=lambda m: True, timeout=5.0) -> SipMessage:
        async def wait():
            while True:
                for i, m in enumerate(self.items):
                    if pred(m):
                        return self.items.pop(i)
                self.event.clear()
                await self.event.wait()
        return await asyncio.wait_for(wait(), timeout)


def is_req(method):
    return lambda m: m.is_request and m.method == method


def is_resp(method, status=None):
    return lambda m: (not m.is_request and m.cseq[1] == method
                      and (status is None or m.status == status))


class FakePhone(asyncio.DatagramProtocol):
    def __init__(self, user: str, password: str, proxy: tuple[str, int]):
        self.user, self.password, self.proxy = user, password, proxy
        self.q = MsgQueue()
        self.transport = None
        self.addr = None
        self.alive = True           # answer OPTIONS?
        self.options_seen = 0
        self.cseq = 1
        self.reg_callid = gen_callid()

    async def start(self):
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(lambda: self, local_addr=("127.0.0.1", 0))
        self.addr = self.transport.get_extra_info("sockname")
        return self

    def connection_made(self, t):
        self.transport = t

    def datagram_received(self, data, addr):
        m = parse_message(data)
        if m.is_request and m.method == "OPTIONS":
            self.options_seen += 1
            if self.alive:
                self.send(make_response(m, 200))
            return
        if not self.alive:
            return
        self.q.put(m)

    def send(self, m: SipMessage, addr=None):
        self.transport.sendto(m.to_bytes(), addr or self.proxy)

    def close(self):
        self.transport.close()

    @property
    def contact(self):
        return f"<sip:{self.user}@{self.addr[0]}:{self.addr[1]}>"

    def new_request(self, method, uri, callid, from_tag, to=None, cseq=None, to_tag=None):
        m = SipMessage.request(method, uri)
        m.add("Via", f"SIP/2.0/UDP {self.addr[0]}:{self.addr[1]};branch={gen_branch()};rport")
        m.add("From", f"<sip:{self.user}@{self.proxy[0]}>;tag={from_tag}")
        m.add("To", (to or f"<{uri}>") + (f";tag={to_tag}" if to_tag else ""))
        m.add("Call-ID", callid)
        if cseq is None:
            self.cseq += 1
            cseq = self.cseq
        m.add("CSeq", f"{cseq} {method}")
        m.add("Contact", self.contact)
        m.add("Max-Forwards", "70")
        return m

    async def register(self, expires=60, password=None, timeout=20) -> SipMessage:
        uri = f"sip:{self.proxy[0]}"
        to = f"<sip:{self.user}@{self.proxy[0]}>"
        tag = gen_tag()
        m = self.new_request("REGISTER", uri, self.reg_callid, tag, to=to)
        m.add("Expires", str(expires))
        self.send(m)
        r = await self.q.get(is_resp("REGISTER"), timeout)
        if r.status == 401:
            m = self.new_request("REGISTER", uri, self.reg_callid, tag, to=to)
            m.add("Expires", str(expires))
            m.add("Authorization", build_authorization(r.get("WWW-Authenticate"), "REGISTER", uri,
                                                       self.user, password or self.password))
            self.send(m)
            r = await self.q.get(is_resp("REGISTER"), timeout)
        return r

    async def invite(self, target: str, body: bytes):
        """Send INVITE answering the 407; returns (invite_msg, callid, from_tag)."""
        uri = f"sip:{target}@{self.proxy[0]}"
        callid, tag = gen_callid(), gen_tag()
        m = self.new_request("INVITE", uri, callid, tag)
        m.add("Content-Type", "application/sdp")
        m.body = body
        self.send(m)
        r = await self.q.get(lambda x: not x.is_request and x.cseq[1] == "INVITE" and x.status >= 200)
        assert r.status == 407, r.status
        ack = SipMessage.request("ACK", uri)
        ack.add("Via", m.get("Via"))
        ack.add("From", m.get("From"))
        ack.add("To", r.get("To"))
        ack.add("Call-ID", callid)
        ack.add("CSeq", f"{m.cseq[0]} ACK")
        self.send(ack)
        m2 = self.new_request("INVITE", uri, callid, tag)
        m2.add("Content-Type", "application/sdp")
        m2.add("Proxy-Authorization", build_authorization(r.get("Proxy-Authenticate"), "INVITE",
                                                          uri, self.user, self.password))
        m2.body = body
        self.send(m2)
        return m2, callid, tag

    def ack_for(self, invite: SipMessage, resp: SipMessage) -> SipMessage:
        contact = resp.get_list("Contact")[0].strip("<>")
        ack = SipMessage.request("ACK", contact)
        ack.add("Via", f"SIP/2.0/UDP {self.addr[0]}:{self.addr[1]};branch={gen_branch()}")
        ack.add("From", invite.get("From"))
        ack.add("To", resp.get("To"))
        ack.add("Call-ID", invite.call_id)
        ack.add("CSeq", f"{invite.cseq[0]} ACK")
        return ack

    def in_dialog(self, method, dialog_req: SipMessage, resp: SipMessage, uas: bool = False):
        """Build an in-dialog request. For UAC dialogs pass the INVITE and its 2xx;
        for UAS dialogs pass the received INVITE and our 2xx with uas=True."""
        if uas:
            target = dialog_req.get_list("Contact")[0].strip("<>")
            frm, to = resp.get("To"), dialog_req.get("From")
        else:
            target = resp.get_list("Contact")[0].strip("<>")
            frm, to = dialog_req.get("From"), resp.get("To")
        m = SipMessage.request(method, target)
        m.add("Via", f"SIP/2.0/UDP {self.addr[0]}:{self.addr[1]};branch={gen_branch()};rport")
        m.add("From", frm)
        m.add("To", to)
        m.add("Call-ID", dialog_req.call_id)
        self.cseq += 1
        m.add("CSeq", f"{self.cseq + 100} {method}")
        m.add("Contact", self.contact)
        m.add("Max-Forwards", "70")
        return m

    def answer(self, invite: SipMessage, status: int, body: bytes = b"", tag: str = "phtag"):
        r = make_response(invite, status, to_tag=tag)
        r.add("Contact", self.contact)
        if body:
            r.add("Content-Type", "application/sdp")
            r.body = body
        self.send(r)
        return r


class FakeRingCentral:
    """Accepts TCP/TLS connections and behaves like a (very) small RingCentral SBC."""

    def __init__(self, auth_id: str, password: str, realm="sip.ringcentral.com",
                 received_ip="203.0.113.7", tls_ctx: ssl.SSLContext | None = None):
        self.auth_id, self.password, self.realm = auth_id, password, realm
        self.received_ip = received_ip
        self.tls_ctx = tls_ctx
        self.q = MsgQueue()
        self.registrations: dict[str, int] = {}
        self.register_log: list[tuple[str, int]] = []
        self.conns: list = []
        self.writer = None
        self.server = None
        self.port = 0
        self.challenge_invites = True
        self.auto_register = True
        self.closed_conns = 0
        self._challenged_acks: set[int] = set()

    async def start(self):
        self.server = await asyncio.start_server(self._client, "127.0.0.1", 0, ssl=self.tls_ctx)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        for w in self.conns:
            w.close()
        self.server.close()

    async def _client(self, reader, writer):
        self.conns.append(writer)
        self.writer = writer
        parser = StreamParser()
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                for kind, raw in parser.feed(data):
                    if kind == "ping":
                        writer.write(b"\r\n")
                    elif kind == "msg":
                        self._on_msg(parse_message(raw), writer)
        finally:
            self.closed_conns += 1

    def send(self, m: SipMessage, writer=None):
        (writer or self.writer).write(m.to_bytes())

    def _nonce(self):
        return secrets.token_hex(8)

    def _check_auth(self, m: SipMessage, header: str) -> bool:
        v = m.get(header)
        if not v:
            return False
        _, p = parse_challenge(v)
        exp = compute_response(p.get("algorithm", "MD5"), p["username"], self.realm, self.password,
                               m.method, p["uri"], p["nonce"], p.get("qop"), p.get("nc"),
                               p.get("cnonce"))
        return p["username"] == self.auth_id and exp == p["response"]

    def _on_msg(self, m: SipMessage, writer):
        if m.is_request:
            via = m.top_via
            via.set_param("received", self.received_ip)
            m.set_top_via(via)
        if m.is_request and m.method == "REGISTER" and self.auto_register:
            if not self._check_auth(m, "Authorization"):
                r = make_response(m, 401)
                r.add("WWW-Authenticate",
                      f'Digest realm="{self.realm}", nonce="{self._nonce()}", algorithm=MD5, qop="auth"')
                self.send(r, writer)
                return
            exp = m.expires_value(3600)
            contact = m.get_list("Contact")[0]
            self.register_log.append((contact, exp))
            if exp == 0:
                self.registrations.pop(contact, None)
            else:
                self.registrations[contact] = exp
            r = make_response(m, 200, to_tag=gen_tag())
            if exp:
                r.add("Contact", f"{contact};expires={min(exp, 300)}")
            self.send(r, writer)
            return
        if m.is_request and m.method == "INVITE" and not m.to_tag and self.challenge_invites:
            if not self._check_auth(m, "Proxy-Authorization"):
                self._challenged_acks.add(m.cseq[0])
                r = make_response(m, 407, to_tag=gen_tag())
                r.add("Proxy-Authenticate",
                      f'Digest realm="{self.realm}", nonce="{self._nonce()}", algorithm=MD5')
                self.send(r, writer)
                return
        if m.is_request and m.method == "ACK" and m.cseq[0] in self._challenged_acks:
            return  # ACK for our own 407
        self.q.put(m)

    # --- helpers for tests ------------------------------------------------
    def respond(self, req: SipMessage, status: int, body: bytes = b"", tag="rctag",
                contact="<sip:rc@127.0.0.1:5090;transport=tcp>"):
        r = make_response(req, status, to_tag=tag)
        if status > 100:
            r.add("Contact", contact)
        if body:
            r.add("Content-Type", "application/sdp")
            r.body = body
        self.send(r)
        return r

    def new_invite(self, to_user: str, body: bytes, caller="+16505550100", display="Caller Name"):
        callid, tag = gen_callid("rc"), gen_tag()
        m = SipMessage.request("INVITE", f"sip:{to_user}@10.0.0.1:5060;transport=tcp")
        m.add("Via", f"SIP/2.0/TCP 127.0.0.1:{self.port};branch={gen_branch()}")
        m.add("From", f'"{display}" <sip:{caller}@sip.ringcentral.com>;tag={tag}')
        m.add("To", f"<sip:{to_user}@sip.ringcentral.com>")
        m.add("Call-ID", callid)
        m.add("CSeq", "101 INVITE")
        m.add("Contact", f"<sip:{caller}@127.0.0.1:{self.port};transport=tcp>")
        m.add("Max-Forwards", "70")
        m.add("Content-Type", "application/sdp")
        m.body = body
        return m

    def in_dialog(self, method, invite: SipMessage, resp: SipMessage, uac=True, cseq=200):
        """Build request in dialog. uac=True when RC sent the INVITE."""
        m = SipMessage.request(method, resp.get_list("Contact")[0].strip("<>") if uac
                               else invite.get_list("Contact")[0].strip("<>"))
        m.add("Via", f"SIP/2.0/TCP 127.0.0.1:{self.port};branch={gen_branch()}")
        if uac:
            m.add("From", invite.get("From"))
            m.add("To", resp.get("To"))
        else:
            m.add("From", resp.get("To"))
            m.add("To", invite.get("From"))
        m.add("Call-ID", invite.call_id)
        m.add("CSeq", f"{cseq} {method}")
        m.add("Max-Forwards", "70")
        return m


def srtp_pair(local_key: bytes, remote_key: bytes, suite="SRTP_PROFILE_AES128_CM_SHA1_80"):
    prof = getattr(pylibsrtp.Policy, suite)
    tx = pylibsrtp.Session(pylibsrtp.Policy(key=local_key, ssrc_type=pylibsrtp.Policy.SSRC_ANY_OUTBOUND, srtp_profile=prof))
    rx = pylibsrtp.Session(pylibsrtp.Policy(key=remote_key, ssrc_type=pylibsrtp.Policy.SSRC_ANY_INBOUND, srtp_profile=prof))
    return tx, rx


def crypto_key(body: bytes, tag: str | None = None) -> tuple[str, str, bytes]:
    s = Sdp.parse(body)
    for c in s.media[0].attrs("crypto"):
        t, suite, inline = c.split()[:3]
        if tag is None or t == tag:
            return t, suite, base64.b64decode(inline[7:])
    raise AssertionError("no crypto line")
