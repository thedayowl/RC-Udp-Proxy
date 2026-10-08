"""RTP/RTCP relay between the phone (LAN, plain RTP) and RingCentral (RTP or SRTP)."""
from __future__ import annotations

import asyncio
import base64
import logging
import random
import secrets
import time

from .sip.sdp import Sdp

log = logging.getLogger("rcproxy.media")

try:
    import pylibsrtp
except ImportError:  # pragma: no cover
    pylibsrtp = None

SUITES = {
    "AES_CM_128_HMAC_SHA1_80": "SRTP_PROFILE_AES128_CM_SHA1_80",
    "AES_CM_128_HMAC_SHA1_32": "SRTP_PROFILE_AES128_CM_SHA1_32",
}
OFFER_SUITES = [(1, "AES_CM_128_HMAC_SHA1_80"), (2, "AES_CM_128_HMAC_SHA1_32")]

STRIP_ATTRS = {
    "crypto", "rtcp", "candidate", "ice-ufrag", "ice-pwd", "ice-options", "ice-lite",
    "ice-mismatch", "remote-candidates", "end-of-candidates", "fingerprint", "setup",
    "group", "msid-semantic",
}


class PortAllocator:
    def __init__(self, lo: int, hi: int):
        self.lo, self.hi = lo + (lo % 2), hi
        self.used: set[int] = set()

    def candidates(self):
        ports = list(range(self.lo, self.hi - 1, 2))
        start = random.randrange(len(ports))
        for p in ports[start:] + ports[:start]:
            if p not in self.used:
                yield p


class _Sock(asyncio.DatagramProtocol):
    def __init__(self, stream: "MediaStream", side: str, rtcp: bool):
        self.stream, self.side, self.rtcp = stream, side, rtcp
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.stream.on_packet(self.side, self.rtcp, data, addr)

    def error_received(self, exc):
        pass

    def sendto(self, data, addr):
        if self.transport is not None:
            self.transport.sendto(data, addr)


def _is_rtcp(pkt: bytes) -> bool:
    # RFC 5761: RTCP packet types 192-223 occupy the second byte
    return len(pkt) >= 2 and 192 <= pkt[1] <= 223


class MediaStream:
    def __init__(self, session: "MediaSession", index: int):
        self.session = session
        self.index = index
        self.socks: dict[tuple[str, bool], _Sock] = {}
        self.ports: dict[str, int] = {}
        # remote addresses learned from SDP / latched from received packets
        self.sdp_addr: dict[str, tuple[str, int] | None] = {"phone": None, "rc": None}
        self.sdp_rtcp: dict[str, tuple[str, int] | None] = {"phone": None, "rc": None}
        self.latched: dict[tuple[str, bool], tuple[str, int]] = {}
        self.packets = {"phone": 0, "rc": 0}
        self.last_rx = {"phone": 0.0, "rc": 0.0}
        self.srtp_errors = 0
        # SRTP state (RingCentral side only)
        self.local_key = secrets.token_bytes(30)
        self.local_suite: str | None = None
        self.remote_key: bytes | None = None
        self.remote_suite: str | None = None
        self.srtp_tx = None   # protects packets sent to RC
        self.srtp_rx = None   # unprotects packets from RC
        self.srtp = False

    async def open(self, alloc: PortAllocator):
        loop = asyncio.get_running_loop()
        for side in ("phone", "rc"):
            for base in alloc.candidates():
                socks = []
                try:
                    for rtcp in (False, True):
                        proto = _Sock(self, side, rtcp)
                        await loop.create_datagram_endpoint(
                            lambda p=proto: p, local_addr=("0.0.0.0", base + int(rtcp)))
                        socks.append(proto)
                except OSError:
                    for s in socks:
                        s.transport.close()
                    continue
                alloc.used.add(base)
                self.ports[side] = base
                self.socks[(side, False)], self.socks[(side, True)] = socks
                break
            else:
                raise RuntimeError("no free RTP ports")

    def close(self, alloc: PortAllocator):
        for s in self.socks.values():
            if s.transport:
                s.transport.close()
        for p in self.ports.values():
            alloc.used.discard(p)
        self.socks.clear()

    # --- SRTP -------------------------------------------------------------
    def configure_srtp(self):
        if not (self.local_suite and self.remote_key and self.remote_suite):
            self.srtp = False
            self.srtp_tx = self.srtp_rx = None
            return
        if pylibsrtp is None:
            raise RuntimeError("pylibsrtp not available")
        tx = pylibsrtp.Policy(key=self.local_key, ssrc_type=pylibsrtp.Policy.SSRC_ANY_OUTBOUND,
                              srtp_profile=getattr(pylibsrtp.Policy, SUITES[self.local_suite]))
        rx = pylibsrtp.Policy(key=self.remote_key, ssrc_type=pylibsrtp.Policy.SSRC_ANY_INBOUND,
                              srtp_profile=getattr(pylibsrtp.Policy, SUITES[self.remote_suite]))
        tx.allow_repeat_tx = True
        self.srtp_tx = pylibsrtp.Session(tx)
        self.srtp_rx = pylibsrtp.Session(rx)
        self.srtp = True

    # --- forwarding --------------------------------------------------------
    def dest(self, side: str, rtcp: bool):
        if (side, rtcp) in self.latched:
            return self.latched[(side, rtcp)]
        return self.sdp_rtcp[side] if rtcp else self.sdp_addr[side]

    def on_packet(self, side: str, rtcp: bool, data: bytes, addr):
        if len(data) < 8:
            return
        other = "rc" if side == "phone" else "phone"
        exp = self.sdp_addr[side]
        # symmetric RTP latching, restricted to the IP signalled in SDP (or phone's IP)
        allowed_ips = {exp[0]} if exp else set()
        if side == "phone" and self.session.phone_ip:
            allowed_ips.add(self.session.phone_ip)
        if addr[0] in allowed_ips or not allowed_ips:
            self.latched[(side, rtcp)] = addr
        elif side == "phone":
            return  # drop media from unexpected LAN hosts
        self.packets[side] += 1
        self.last_rx[side] = time.time()
        is_rtcp = rtcp or _is_rtcp(data)
        try:
            if self.srtp:
                if side == "rc":
                    data = self.srtp_rx.unprotect_rtcp(data) if is_rtcp else self.srtp_rx.unprotect(data)
                else:
                    data = self.srtp_tx.protect_rtcp(data) if is_rtcp else self.srtp_tx.protect(data)
        except Exception:  # noqa: BLE001
            self.srtp_errors += 1
            return
        dst = self.dest(other, rtcp)
        if dst is None or dst[0] == "0.0.0.0" or dst[1] == 0:
            return
        self.socks[(other, rtcp)].sendto(data, dst)


class MediaSession:
    """Owns the relay sockets for one call and rewrites SDP passing through."""

    def __init__(self, core, endpoint, phone_ip: str | None):
        self.core = core
        self.endpoint = endpoint
        self.phone_ip = phone_ip
        self.streams: list[MediaStream] = []
        self.sess_id = str(random.randint(10**8, 10**9))
        self.out_version = {"phone": random.randint(1, 1000), "rc": random.randint(1, 1000)}
        self.in_version: dict[str, str | None] = {"phone": None, "rc": None}
        self.closed = False

    @property
    def srtp(self) -> bool:
        return any(s.srtp for s in self.streams)

    def stats(self):
        return [{"index": s.index, "phone_port": s.ports.get("phone"), "rc_port": s.ports.get("rc"),
                 "from_phone": s.packets["phone"], "from_rc": s.packets["rc"],
                 "srtp": s.srtp, "srtp_errors": s.srtp_errors,
                 "phone_remote": "%s:%s" % s.dest("phone", False) if s.dest("phone", False) else None,
                 "rc_remote": "%s:%s" % s.dest("rc", False) if s.dest("rc", False) else None}
                for s in self.streams]

    async def _stream(self, i: int) -> MediaStream:
        while len(self.streams) <= i:
            st = MediaStream(self, len(self.streams))
            await st.open(self.core.ports)
            self.streams.append(st)
        return self.streams[i]

    def close(self):
        if self.closed:
            return
        self.closed = True
        for s in self.streams:
            s.close(self.core.ports)

    def local_ip(self, side: str) -> str:
        if side == "phone":
            return self.core.lan_ip
        return self.endpoint.media_public_ip()

    async def rewrite(self, body: bytes, from_side: str, to_side: str, is_offer: bool) -> bytes:
        """Rewrite an SDP body travelling from_side -> to_side so media flows via us."""
        sdp = Sdp.parse(body)
        origin = sdp.origin
        version = origin[2] if len(origin) >= 3 else None
        if version != self.in_version[from_side]:
            self.in_version[from_side] = version
            self.out_version[to_side] += 1
        ip = self.local_ip(to_side)
        out = ["v=0", f"o=rcproxy {self.sess_id} {self.out_version[to_side]} IN IP4 {ip}"]
        sline = next((ln for ln in sdp.session if ln.startswith("s=")), "s=-")
        out.append(sline)
        out.append(f"c=IN IP4 {ip}")
        for ln in sdp.session:
            if ln[:2] in ("v=", "o=", "s=", "c="):
                continue
            if ln.startswith("a=") and ln[2:].partition(":")[0] in STRIP_ATTRS:
                continue
            out.append(ln)

        for i, m in enumerate(sdp.media):
            st = await self._stream(i)
            cip = sdp.media_connection(m)
            if m.port == 0:
                out.append(f"m={m.media} 0 {self._proto(m, to_side, st, is_offer, False)} {' '.join(m.fmts)}")
                out.extend(ln for ln in m.lines if not ln.startswith("c="))
                continue
            rtcp_port = m.port + 1
            for v in m.attrs("rtcp"):
                try:
                    rtcp_port = int(v.split()[0])
                except ValueError:
                    pass
            if m.has_attr("rtcp-mux"):
                rtcp_port = m.port
            if cip:
                st.sdp_addr[from_side] = (cip, m.port)
                st.sdp_rtcp[from_side] = (cip, rtcp_port)
                # remote moved: drop old latch so the new SDP address is used
                for rt in (False, True):
                    la = st.latched.get((from_side, rt))
                    if la and la[0] != cip:
                        st.latched.pop((from_side, rt), None)

            # --- SRTP negotiation on the RingCentral side -----------------
            srtp_out = False
            answer_crypto = None
            if from_side == "rc":
                cryptos = m.attrs("crypto") if "SAVP" in m.proto.upper() else []
                chosen = None
                for c in cryptos:
                    parts = c.split()
                    if len(parts) >= 3 and parts[1] in SUITES and parts[2].startswith("inline:"):
                        chosen = parts
                        break
                if chosen:
                    st.remote_suite = chosen[1]
                    st.remote_key = base64.b64decode(chosen[2][7:].split("|")[0] + "==")[:30]
                    if is_offer:
                        st.local_suite = chosen[1]
                        st.answer_tag = chosen[0]
                    else:
                        # answer to our offer: tag tells which suite we sent
                        tag = int(chosen[0]) if chosen[0].isdigit() else 1
                        st.local_suite = dict(OFFER_SUITES).get(tag, chosen[1])
                    st.configure_srtp()
                elif not is_offer or not cryptos:
                    st.remote_key = st.remote_suite = st.local_suite = None
                    st.configure_srtp()
            else:  # to RingCentral
                if is_offer:
                    srtp_out = self.endpoint.cfg.srtp == "sdes" or st.srtp
                else:
                    srtp_out = st.srtp
                    if srtp_out:
                        answer_crypto = (getattr(st, "answer_tag", "1"), st.local_suite)

            proto = self._proto(m, to_side, st, is_offer, srtp_out)
            out.append(f"m={m.media} {st.ports[to_side]} {proto} {' '.join(m.fmts)}")
            for ln in m.lines:
                if ln.startswith("c="):
                    continue
                if ln.startswith("a=") and ln[2:].partition(":")[0] in STRIP_ATTRS:
                    continue
                out.append(ln)
            if not m.has_attr("rtcp-mux"):
                out.append(f"a=rtcp:{st.ports[to_side] + 1}")
            if srtp_out:
                key = base64.b64encode(st.local_key).decode()
                if answer_crypto:
                    out.append(f"a=crypto:{answer_crypto[0]} {answer_crypto[1]} inline:{key}")
                else:
                    for tag, suite in OFFER_SUITES:
                        out.append(f"a=crypto:{tag} {suite} inline:{key}")
        return ("\r\n".join(out) + "\r\n").encode()

    @staticmethod
    def _proto(m, to_side, st, is_offer, srtp_out) -> str:
        proto = m.proto
        if to_side == "phone":
            return proto.replace("SAVP", "AVP") if "RTP/" in proto.upper() else proto
        if "RTP/" not in proto.upper():
            return proto
        if srtp_out:
            return proto.replace("RTP/AVP", "RTP/SAVP") if "SAVP" not in proto else proto
        return proto.replace("SAVP", "AVP")
