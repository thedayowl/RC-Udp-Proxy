"""Minimal SDP model sufficient for rewriting media addresses (RFC 4566)."""
from __future__ import annotations


class SdpMedia:
    def __init__(self, mline: str):
        parts = mline.split()
        self.media = parts[0]
        self.port = int(parts[1].split("/")[0])
        self.proto = parts[2] if len(parts) > 2 else "RTP/AVP"
        self.fmts = parts[3:]
        self.lines: list[str] = []   # every line after m= (without the m= line)

    @property
    def connection(self) -> str | None:
        for ln in self.lines:
            if ln.startswith("c="):
                return ln[2:].split()[-1].split("/")[0]
        return None

    def attrs(self, name: str) -> list[str]:
        out = []
        for ln in self.lines:
            if ln.startswith("a="):
                k, _, v = ln[2:].partition(":")
                if k == name:
                    out.append(v)
        return out

    def has_attr(self, name: str) -> bool:
        return any(ln == f"a={name}" or ln.startswith(f"a={name}:") for ln in self.lines)

    @property
    def direction(self) -> str:
        for d in ("sendrecv", "sendonly", "recvonly", "inactive"):
            if self.has_attr(d):
                return d
        return "sendrecv"


class Sdp:
    def __init__(self):
        self.session: list[str] = []
        self.media: list[SdpMedia] = []

    @classmethod
    def parse(cls, body: bytes | str) -> "Sdp":
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        s = cls()
        for ln in body.replace("\r\n", "\n").split("\n"):
            ln = ln.strip()
            if not ln or len(ln) < 2 or ln[1] != "=":
                continue
            if ln.startswith("m="):
                s.media.append(SdpMedia(ln[2:]))
            elif s.media:
                s.media[-1].lines.append(ln)
            else:
                s.session.append(ln)
        if not any(ln.startswith("v=") for ln in s.session):
            raise ValueError("not an SDP body")
        return s

    @property
    def connection(self) -> str | None:
        for ln in self.session:
            if ln.startswith("c="):
                return ln[2:].split()[-1].split("/")[0]
        return None

    @property
    def origin(self) -> list[str]:
        for ln in self.session:
            if ln.startswith("o="):
                return ln[2:].split()
        return []

    def session_attrs(self, name: str) -> list[str]:
        out = []
        for ln in self.session:
            if ln.startswith("a="):
                k, _, v = ln[2:].partition(":")
                if k == name:
                    out.append(v)
        return out

    def media_connection(self, m: SdpMedia) -> str | None:
        return m.connection or self.connection

    def media_direction(self, m: SdpMedia) -> str:
        for d in ("sendrecv", "sendonly", "recvonly", "inactive"):
            if m.has_attr(d):
                return d
        for d in ("sendonly", "recvonly", "inactive"):
            if f"a={d}" in self.session:
                return d
        return "sendrecv"
