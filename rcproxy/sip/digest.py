"""HTTP Digest authentication for SIP (RFC 2617 / RFC 8760)."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

_ALGS = {
    "MD5": hashlib.md5,
    "MD5-SESS": hashlib.md5,
    "SHA-256": hashlib.sha256,
    "SHA-256-SESS": hashlib.sha256,
}


def parse_challenge(value: str) -> tuple[str, dict[str, str]]:
    """Parse 'Digest realm="x", nonce="y", qop="auth"' -> ('Digest', {...})."""
    value = value.strip()
    scheme, _, rest = value.partition(" ")
    params: dict[str, str] = {}
    i, n = 0, len(rest)
    while i < n:
        while i < n and rest[i] in " ,\t":
            i += 1
        eq = rest.find("=", i)
        if eq < 0:
            break
        key = rest[i:eq].strip().lower()
        i = eq + 1
        while i < n and rest[i] == " ":
            i += 1
        if i < n and rest[i] == '"':
            j = i + 1
            buf = []
            while j < n and rest[j] != '"':
                if rest[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(rest[j])
                j += 1
            params[key] = "".join(buf)
            i = j + 1
        else:
            j = rest.find(",", i)
            if j < 0:
                j = n
            params[key] = rest[i:j].strip()
            i = j
    return scheme, params


def _h(alg: str, s: str) -> str:
    return _ALGS.get(alg.upper(), hashlib.md5)(s.encode("utf-8")).hexdigest()


def compute_response(alg, username, realm, password, method, uri, nonce,
                     qop=None, nc=None, cnonce=None, body=b"") -> str:
    alg = (alg or "MD5").upper()
    ha1 = _h(alg, f"{username}:{realm}:{password}")
    if alg.endswith("-SESS"):
        ha1 = _h(alg, f"{ha1}:{nonce}:{cnonce}")
    if qop == "auth-int":
        ha2 = _h(alg, f"{method}:{uri}:{_h(alg, body.decode('latin-1'))}")
    else:
        ha2 = _h(alg, f"{method}:{uri}")
    if qop:
        return _h(alg, f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    return _h(alg, f"{ha1}:{nonce}:{ha2}")


def build_authorization(challenge: str, method: str, uri: str, username: str,
                        password: str, nc: int = 1) -> str:
    """Build an Authorization / Proxy-Authorization value for a challenge."""
    _, p = parse_challenge(challenge)
    alg = p.get("algorithm", "MD5")
    if alg.upper() not in _ALGS:
        raise ValueError(f"unsupported digest algorithm {alg}")
    qop = None
    if "qop" in p:
        opts = [q.strip() for q in p["qop"].split(",")]
        qop = "auth" if "auth" in opts else None
    cnonce = secrets.token_hex(8)
    ncs = f"{nc:08x}"
    resp = compute_response(alg, username, p.get("realm", ""), password, method, uri,
                            p.get("nonce", ""), qop, ncs, cnonce)
    parts = [
        f'username="{username}"', f'realm="{p.get("realm", "")}"',
        f'nonce="{p.get("nonce", "")}"', f'uri="{uri}"', f'response="{resp}"',
        f"algorithm={alg}",
    ]
    if qop:
        parts += [f"qop={qop}", f"nc={ncs}", f'cnonce="{cnonce}"']
    if "opaque" in p:
        parts.append(f'opaque="{p["opaque"]}"')
    return "Digest " + ", ".join(parts)


class DigestServer:
    """Issues and verifies stateless (HMAC-signed) nonces."""

    NONCE_TTL = 300

    def __init__(self, realm: str):
        self.realm = realm
        self._secret = secrets.token_bytes(32)

    def _sign(self, ts: str) -> str:
        return hmac.new(self._secret, ts.encode(), hashlib.sha256).hexdigest()[:24]

    def challenge(self, stale: bool = False) -> str:
        ts = f"{int(time.time()):x}"
        nonce = f"{ts}{self._sign(ts)}"
        s = f'Digest realm="{self.realm}", nonce="{nonce}", algorithm=MD5, qop="auth"'
        if stale:
            s += ", stale=TRUE"
        return s

    def _nonce_ok(self, nonce: str) -> tuple[bool, bool]:
        """Return (valid_signature, fresh)."""
        if len(nonce) < 25:
            return False, False
        ts, sig = nonce[:-24], nonce[-24:]
        if not hmac.compare_digest(sig, self._sign(ts)):
            return False, False
        try:
            age = time.time() - int(ts, 16)
        except ValueError:
            return False, False
        return True, 0 <= age <= self.NONCE_TTL

    def verify(self, header_value: str | None, method: str, lookup) -> tuple[str, str | None]:
        """Verify credentials.

        lookup(username) -> password or None.
        Returns (result, username) where result is 'ok', 'stale', 'missing' or 'fail'.
        """
        if not header_value:
            return "missing", None
        scheme, p = parse_challenge(header_value)
        if scheme.lower() != "digest":
            return "fail", None
        user = p.get("username")
        if not user:
            return "fail", None
        if p.get("realm") != self.realm:
            return "missing", user
        valid, fresh = self._nonce_ok(p.get("nonce", ""))
        if not valid:
            return "missing", user
        password = lookup(user)
        if password is None:
            return "fail", user
        qop = p.get("qop")
        expected = compute_response(p.get("algorithm", "MD5"), user, self.realm, password,
                                    method, p.get("uri", ""), p.get("nonce", ""),
                                    qop, p.get("nc"), p.get("cnonce"))
        if not hmac.compare_digest(expected, p.get("response", "")):
            return "fail", user
        if not fresh:
            return "stale", user
        return "ok", user
