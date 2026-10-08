"""SIP message parsing / serialisation and header helpers (RFC 3261)."""
from __future__ import annotations

import re
import secrets

COMPACT = {
    "i": "Call-ID", "m": "Contact", "e": "Content-Encoding", "l": "Content-Length",
    "c": "Content-Type", "f": "From", "s": "Subject", "k": "Supported", "t": "To",
    "v": "Via", "o": "Event", "r": "Refer-To", "b": "Referred-By", "u": "Allow-Events",
    "x": "Session-Expires",
}

_WELL_KNOWN = [
    "Via", "From", "To", "Call-ID", "CSeq", "Contact", "Max-Forwards", "Route",
    "Record-Route", "Content-Type", "Content-Length", "Expires", "Min-Expires",
    "Authorization", "Proxy-Authorization", "WWW-Authenticate", "Proxy-Authenticate",
    "Allow", "Supported", "Require", "Proxy-Require", "Unsupported", "User-Agent",
    "Server", "Event", "Allow-Events", "Subscription-State", "Refer-To", "Referred-By",
    "Replaces", "Session-Expires", "Min-SE", "Alert-Info", "Call-Info", "Reason",
    "Warning", "Retry-After", "Accept", "P-Asserted-Identity", "Remote-Party-ID",
    "Content-Disposition", "Date", "Diversion", "Privacy", "RSeq", "RAck", "Subject",
]
_CANON = {n.lower(): n for n in _WELL_KNOWN}
_CANON["call-id"] = "Call-ID"
_CANON["cseq"] = "CSeq"
_CANON["www-authenticate"] = "WWW-Authenticate"

# Headers whose values may be comma-joined lists.
LIST_HEADERS = {
    "via", "route", "record-route", "contact", "allow", "supported", "require",
    "proxy-require", "unsupported", "allow-events", "accept",
}

REASONS = {
    100: "Trying", 180: "Ringing", 181: "Call Is Being Forwarded", 182: "Queued",
    183: "Session Progress", 200: "OK", 202: "Accepted", 400: "Bad Request",
    401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
    407: "Proxy Authentication Required", 408: "Request Timeout", 415: "Unsupported Media Type",
    420: "Bad Extension", 423: "Interval Too Brief", 480: "Temporarily Unavailable",
    481: "Call/Transaction Does Not Exist", 482: "Loop Detected", 483: "Too Many Hops",
    486: "Busy Here", 487: "Request Terminated", 488: "Not Acceptable Here",
    489: "Bad Event", 491: "Request Pending", 500: "Server Internal Error",
    501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable",
    504: "Server Time-out", 600: "Busy Everywhere", 603: "Decline",
}


def canon(name: str) -> str:
    n = name.strip()
    if len(n) == 1:
        n = COMPACT.get(n.lower(), n)
    return _CANON.get(n.lower(), n)


def gen_tag() -> str:
    return secrets.token_hex(6)


def gen_branch() -> str:
    return "z9hG4bK" + secrets.token_hex(10)


def gen_callid(host: str = "") -> str:
    cid = secrets.token_hex(12)
    return f"{cid}@{host}" if host else cid


def split_list(value: str) -> list[str]:
    """Split a comma-separated header value, honouring quotes and <>."""
    out, cur, quote, angle, esc = [], [], False, False, False
    for ch in value:
        if esc:
            cur.append(ch)
            esc = False
            continue
        if ch == "\\" and quote:
            esc = True
        elif ch == '"':
            quote = not quote
        elif ch == "<" and not quote:
            angle = True
        elif ch == ">" and not quote:
            angle = False
        elif ch == "," and not quote and not angle:
            item = "".join(cur).strip()
            if item:
                out.append(item)
            cur = []
            continue
        cur.append(ch)
    item = "".join(cur).strip()
    if item:
        out.append(item)
    return out


def parse_params(s: str) -> list[list[str | None]]:
    """Parse ';a=b;c' into [[a,b],[c,None]] (quote-aware)."""
    params = []
    for part in _split_unquoted(s, ";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            params.append([k.strip(), v.strip()])
        else:
            params.append([part, None])
    return params


def _split_unquoted(s: str, sep: str) -> list[str]:
    out, cur, quote = [], [], False
    for ch in s:
        if ch == '"':
            quote = not quote
        if ch == sep and not quote:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def format_params(params) -> str:
    return "".join(f";{k}" if v is None else f";{k}={v}" for k, v in params)


def _get_param(params, name):
    for k, v in params:
        if k.lower() == name.lower():
            return v if v is not None else ""
    return None


def _set_param(params, name, value):
    for p in params:
        if p[0].lower() == name.lower():
            p[1] = value
            return
    params.append([name, value])


def _del_param(params, name):
    params[:] = [p for p in params if p[0].lower() != name.lower()]


class SipUri:
    _re = re.compile(r"^(?P<scheme>sips?|tel):(?P<rest>.*)$", re.I)

    def __init__(self, scheme="sip", user=None, host="", port=None, params=None, headers=""):
        self.scheme = scheme
        self.user = user
        self.password = None
        self.host = host
        self.port = port
        self.params = params or []
        self.headers = headers

    @classmethod
    def parse(cls, s: str) -> "SipUri":
        s = s.strip()
        m = cls._re.match(s)
        if not m:
            raise ValueError(f"bad uri: {s!r}")
        u = cls(scheme=m.group("scheme").lower())
        rest = m.group("rest")
        if "?" in rest:
            rest, u.headers = rest.split("?", 1)
        if u.scheme == "tel":
            parts = rest.split(";", 1)
            u.user = parts[0]
            u.params = parse_params(parts[1]) if len(parts) > 1 else []
            return u
        if "@" in rest:
            userinfo, rest = rest.rsplit("@", 1)
            if ":" in userinfo:
                userinfo, u.password = userinfo.split(":", 1)
            u.user = userinfo
        hostport, _, params = rest.partition(";")
        u.params = parse_params(params)
        if hostport.startswith("["):
            end = hostport.index("]")
            u.host = hostport[: end + 1]
            pp = hostport[end + 1:]
            if pp.startswith(":"):
                u.port = int(pp[1:])
        elif ":" in hostport:
            h, p = hostport.rsplit(":", 1)
            u.host, u.port = h, int(p)
        else:
            u.host = hostport
        return u

    def param(self, name):
        return _get_param(self.params, name)

    def set_param(self, name, value=None):
        _set_param(self.params, name, value)

    def del_param(self, name):
        _del_param(self.params, name)

    def __str__(self):
        if self.scheme == "tel":
            s = f"tel:{self.user}{format_params(self.params)}"
        else:
            s = f"{self.scheme}:"
            if self.user is not None:
                s += self.user
                if self.password is not None:
                    s += ":" + self.password
                s += "@"
            s += self.host
            if self.port:
                s += f":{self.port}"
            s += format_params(self.params)
        if self.headers:
            s += "?" + self.headers
        return s


class NameAddr:
    """name-addr / addr-spec with header parameters, e.g. From/To/Contact values."""

    def __init__(self, uri: str, display: str | None = None, params=None):
        self.uri = uri
        self.display = display
        self.params = params or []

    @classmethod
    def parse(cls, s: str) -> "NameAddr":
        s = s.strip()
        # find '<' outside quotes
        quote = False
        lt = -1
        for i, ch in enumerate(s):
            if ch == '"':
                quote = not quote
            elif ch == "<" and not quote:
                lt = i
                break
        if lt >= 0:
            gt = s.index(">", lt)
            display = s[:lt].strip() or None
            uri = s[lt + 1: gt].strip()
            params = parse_params(s[gt + 1:])
        else:
            uri, _, rest = s.partition(";")
            display = None
            params = parse_params(rest)
            uri = uri.strip()
        return cls(uri, display, params)

    @property
    def tag(self):
        return _get_param(self.params, "tag")

    def param(self, name):
        return _get_param(self.params, name)

    def set_param(self, name, value=None):
        _set_param(self.params, name, value)

    def del_param(self, name):
        _del_param(self.params, name)

    @property
    def sip_uri(self) -> SipUri:
        return SipUri.parse(self.uri)

    @property
    def display_name(self) -> str:
        if not self.display:
            return ""
        d = self.display
        if d.startswith('"') and d.endswith('"'):
            d = d[1:-1].replace('\\"', '"')
        return d

    def __str__(self):
        s = f"<{self.uri}>"
        if self.display:
            s = f"{self.display} {s}"
        return s + format_params(self.params)


class Via:
    def __init__(self, transport="UDP", host="", port=None, params=None):
        self.transport = transport
        self.host = host
        self.port = port
        self.params = params or []

    @classmethod
    def parse(cls, s: str) -> "Via":
        s = s.strip()
        proto, _, rest = s.partition(" ")
        parts = proto.split("/")
        transport = parts[-1].strip().upper() if len(parts) >= 3 else "UDP"
        rest = rest.strip()
        sentby, _, params = rest.partition(";")
        sentby = sentby.strip()
        port = None
        if sentby.startswith("["):
            end = sentby.index("]")
            host = sentby[: end + 1]
            if sentby[end + 1:].startswith(":"):
                port = int(sentby[end + 2:])
        elif ":" in sentby:
            host, p = sentby.rsplit(":", 1)
            port = int(p)
        else:
            host = sentby
        return cls(transport, host, port, parse_params(params))

    @property
    def branch(self):
        return _get_param(self.params, "branch")

    def param(self, name):
        return _get_param(self.params, name)

    def set_param(self, name, value=None):
        _set_param(self.params, name, value)

    def __str__(self):
        hp = self.host + (f":{self.port}" if self.port else "")
        return f"SIP/2.0/{self.transport} {hp}{format_params(self.params)}"


class SipMessage:
    def __init__(self):
        self.method: str | None = None
        self.uri: str | None = None
        self.status: int | None = None
        self.reason: str = ""
        self.headers: list[list[str]] = []
        self.body: bytes = b""

    # --- construction -------------------------------------------------
    @classmethod
    def request(cls, method: str, uri: str) -> "SipMessage":
        m = cls()
        m.method, m.uri = method, str(uri)
        return m

    @classmethod
    def response(cls, status: int, reason: str | None = None) -> "SipMessage":
        m = cls()
        m.status = status
        m.reason = reason or REASONS.get(status, "Unknown")
        return m

    @property
    def is_request(self) -> bool:
        return self.method is not None

    # --- header access -----------------------------------------------
    def get(self, name: str, default=None):
        ln = canon(name).lower()
        for k, v in self.headers:
            if k.lower() == ln:
                return v
        return default

    def get_all(self, name: str) -> list[str]:
        ln = canon(name).lower()
        return [v for k, v in self.headers if k.lower() == ln]

    def get_list(self, name: str) -> list[str]:
        out = []
        for v in self.get_all(name):
            out.extend(split_list(v))
        return out

    def set(self, name: str, value) -> None:
        n = canon(name)
        ln = n.lower()
        for i, (k, _) in enumerate(self.headers):
            if k.lower() == ln:
                self.headers[i] = [n, str(value)]
                self.headers = [h for j, h in enumerate(self.headers) if j <= i or h[0].lower() != ln]
                return
        self.headers.append([n, str(value)])

    def add(self, name: str, value, top: bool = False) -> None:
        n = canon(name)
        if top:
            idx = next((i for i, (k, _) in enumerate(self.headers) if k.lower() == n.lower()), 0)
            self.headers.insert(idx, [n, str(value)])
        else:
            self.headers.append([n, str(value)])

    def remove(self, name: str) -> None:
        ln = canon(name).lower()
        self.headers = [h for h in self.headers if h[0].lower() != ln]

    def copy(self) -> "SipMessage":
        m = SipMessage()
        m.method, m.uri, m.status, m.reason = self.method, self.uri, self.status, self.reason
        m.headers = [list(h) for h in self.headers]
        m.body = self.body
        return m

    # --- common fields ------------------------------------------------
    @property
    def call_id(self) -> str:
        return self.get("Call-ID", "")

    @property
    def cseq(self) -> tuple[int, str]:
        v = self.get("CSeq", "0 X").split()
        return int(v[0]), v[1].upper() if len(v) > 1 else ""

    @property
    def from_hdr(self) -> NameAddr:
        return NameAddr.parse(self.get("From", ""))

    @property
    def to_hdr(self) -> NameAddr:
        return NameAddr.parse(self.get("To", ""))

    @property
    def from_tag(self):
        return self.from_hdr.tag

    @property
    def to_tag(self):
        return self.to_hdr.tag

    @property
    def vias(self) -> list[str]:
        return self.get_list("Via")

    @property
    def top_via(self) -> Via | None:
        v = self.vias
        return Via.parse(v[0]) if v else None

    def set_top_via(self, via: Via) -> None:
        vias = self.vias
        vias[0] = str(via)
        self.remove("Via")
        for v in vias:
            self.add("Via", v)
        # keep Via first in header order for readability
        self.headers.sort(key=lambda h: 0 if h[0] == "Via" else 1)

    @property
    def content_type(self) -> str:
        return (self.get("Content-Type") or "").split(";")[0].strip().lower()

    @property
    def has_sdp(self) -> bool:
        return bool(self.body.strip()) and self.content_type == "application/sdp"

    def expires_value(self, default=None):
        v = self.get("Expires")
        try:
            return int(v) if v is not None else default
        except ValueError:
            return default

    # --- serialisation ------------------------------------------------
    def first_line(self) -> str:
        if self.is_request:
            return f"{self.method} {self.uri} SIP/2.0"
        return f"SIP/2.0 {self.status} {self.reason}"

    def to_bytes(self) -> bytes:
        lines = [self.first_line()]
        for k, v in self.headers:
            if k == "Content-Length":
                continue
            lines.append(f"{k}: {v}")
        lines.append(f"Content-Length: {len(self.body)}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + self.body

    def __str__(self):
        return self.to_bytes().decode("utf-8", "replace")

    def summary(self) -> str:
        if self.is_request:
            return f"{self.method} {self.uri}"
        return f"{self.status} {self.reason} ({self.cseq[1]})"


def parse_message(data: bytes) -> SipMessage:
    sep = data.find(b"\r\n\r\n")
    if sep >= 0:
        head, body = data[:sep], data[sep + 4:]
    else:
        sep = data.find(b"\n\n")
        if sep < 0:
            head, body = data, b""
        else:
            head, body = data[:sep], data[sep + 2:]
    text = head.decode("utf-8", "replace")
    raw_lines = re.split(r"\r?\n", text)
    # unfold continuation lines
    lines: list[str] = []
    for ln in raw_lines:
        if ln[:1] in (" ", "\t") and lines:
            lines[-1] += " " + ln.strip()
        else:
            lines.append(ln)
    if not lines or not lines[0]:
        raise ValueError("empty message")
    m = SipMessage()
    first = lines[0].strip()
    if first.startswith("SIP/2.0"):
        parts = first.split(" ", 2)
        m.status = int(parts[1])
        m.reason = parts[2] if len(parts) > 2 else ""
    else:
        parts = first.split(" ")
        if len(parts) != 3 or not parts[2].startswith("SIP/"):
            raise ValueError(f"bad request line: {first!r}")
        m.method, m.uri = parts[0].upper(), parts[1]
    for ln in lines[1:]:
        if not ln.strip():
            continue
        if ":" not in ln:
            raise ValueError(f"bad header line: {ln!r}")
        k, v = ln.split(":", 1)
        m.headers.append([canon(k), v.strip()])
    cl = m.get("Content-Length")
    if cl is not None:
        try:
            n = int(cl)
            body = body[:n]
        except ValueError:
            pass
    m.body = body
    return m


def make_response(req: SipMessage, status: int, reason: str | None = None,
                  to_tag: str | None = None) -> SipMessage:
    r = SipMessage.response(status, reason)
    for v in req.get_all("Via"):
        r.add("Via", v)
    r.add("From", req.get("From", ""))
    to = req.get("To", "")
    if to_tag and status > 100:
        na = NameAddr.parse(to)
        if not na.tag:
            na.set_param("tag", to_tag)
            to = str(na)
    r.add("To", to)
    r.add("Call-ID", req.call_id)
    r.add("CSeq", req.get("CSeq", ""))
    return r


class StreamParser:
    """Frames SIP messages out of a byte stream (TCP/TLS)."""

    MAX = 256 * 1024

    def __init__(self):
        self.buf = b""

    def feed(self, data: bytes):
        """Yield ('ping'|'pong'|'msg', payload)."""
        self.buf += data
        while True:
            # keep-alives (RFC 5626): CRLFCRLF ping / CRLF pong
            if self.buf.startswith(b"\r\n\r\n"):
                self.buf = self.buf[4:]
                yield "ping", None
                continue
            if self.buf.startswith(b"\r\n"):
                if len(self.buf) < 4 and b"\r\n\r\n".startswith(self.buf):
                    # could still become a ping; a pong is resolved on next data
                    return
                self.buf = self.buf[2:]
                yield "pong", None
                continue
            sep = self.buf.find(b"\r\n\r\n")
            if sep < 0:
                if len(self.buf) > self.MAX:
                    raise ValueError("header too large")
                return
            head = self.buf[:sep].decode("utf-8", "replace")
            clen = 0
            for ln in head.split("\r\n")[1:]:
                k, _, v = ln.partition(":")
                if canon(k) == "Content-Length":
                    try:
                        clen = int(v.strip())
                    except ValueError:
                        clen = 0
            total = sep + 4 + clen
            if len(self.buf) < total:
                return
            raw, self.buf = self.buf[:total], self.buf[total:]
            yield "msg", raw
