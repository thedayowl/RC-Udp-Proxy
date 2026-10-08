"""Persistent configuration (JSON file in the data volume)."""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import uuid
from dataclasses import dataclass, field

DATA_DIR = os.environ.get("RCPROXY_DATA", "/data")


@dataclass
class Settings:
    lan_ip: str = ""              # address advertised to phones (blank = auto-detect)
    public_ip: str = ""           # address advertised to RingCentral in SDP (blank = auto)
    sip_port: int = 5060          # UDP port phones register to
    rtp_port_min: int = 20000
    rtp_port_max: int = 20999
    realm: str = "rc-udp-proxy"
    phone_max_expires: int = 300
    phone_min_expires: int = 60
    options_interval: int = 30    # seconds between OPTIONS pings to each phone
    options_max_failures: int = 3
    rc_register_expires: int = 600
    tls_verify: bool = True
    sip_trace: bool = False
    log_level: str = "INFO"
    admin_user: str = "admin"
    admin_password_hash: str = ""


@dataclass
class Endpoint:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    name: str = ""
    enabled: bool = True
    # Credentials the UDP phone uses to register to this proxy
    phone_username: str = ""
    phone_password: str = ""
    # Values provided by RingCentral for the device
    rc_sip_domain: str = "sip.ringcentral.com"
    rc_outbound_proxy: str = ""
    rc_username: str = ""
    rc_password: str = ""
    rc_auth_id: str = ""
    rc_transport: str = "tls"     # "tls" or "tcp"
    srtp: str = "off"             # "off" or "sdes" (offer SRTP towards RingCentral)

    def proxy_hostport(self) -> tuple[str, int]:
        v = self.rc_outbound_proxy.strip()
        v = re.sub(r"^sips?:", "", v, flags=re.I).split(";")[0]
        default = 5061 if self.rc_transport == "tls" else 5060
        if v.startswith("["):
            host, _, rest = v[1:].partition("]")
            return host, int(rest[1:]) if rest.startswith(":") else default
        if ":" in v:
            host, port = v.rsplit(":", 1)
            return host, int(port)
        return v, default


SECRET_FIELDS = {"phone_password", "rc_password"}


def hash_password(pw: str) -> str:
    salt = secrets.token_hex(8)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()
    return f"pbkdf2${salt}${dk}"


def check_password(pw: str, stored: str) -> bool:
    try:
        _, salt, dk = stored.split("$")
    except ValueError:
        return False
    calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()
    return hmac.compare_digest(calc, dk)


def detect_lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))  # no packets are sent
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _from_dict(cls, d: dict):
    names = {f.name: f for f in dataclasses.fields(cls)}
    kwargs = {}
    for k, v in (d or {}).items():
        if k not in names:
            continue
        default = cls().__getattribute__(k)
        if isinstance(default, bool):
            v = v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")
        elif isinstance(default, int):
            v = int(v)
        elif isinstance(default, str):
            v = "" if v is None else str(v).strip()
        kwargs[k] = v
    return cls(**kwargs)


class ValidationError(ValueError):
    pass


def validate_endpoint(ep: Endpoint, others: list[Endpoint]):
    if not ep.phone_username:
        raise ValidationError("Phone username is required")
    if not re.fullmatch(r"[A-Za-z0-9_.\-+]+", ep.phone_username):
        raise ValidationError("Phone username may only contain letters, digits, _ . - +")
    if not ep.phone_password:
        raise ValidationError("Phone password is required")
    for o in others:
        if o.id != ep.id and o.phone_username == ep.phone_username:
            raise ValidationError(f"Phone username '{ep.phone_username}' is already used")
    for f in ("rc_sip_domain", "rc_outbound_proxy", "rc_username", "rc_password", "rc_auth_id"):
        if not getattr(ep, f):
            raise ValidationError(f"{f.replace('rc_', 'RingCentral ').replace('_', ' ')} is required")
    if ep.rc_transport not in ("tls", "tcp"):
        raise ValidationError("Transport must be tls or tcp")
    if ep.srtp not in ("off", "sdes"):
        raise ValidationError("SRTP must be off or sdes")
    try:
        ep.proxy_hostport()
    except ValueError:
        raise ValidationError("Outbound proxy must be host or host:port") from None


def validate_settings(s: Settings):
    if not (1 <= s.sip_port <= 65535):
        raise ValidationError("SIP port out of range")
    if not (1024 <= s.rtp_port_min < s.rtp_port_max <= 65535):
        raise ValidationError("Invalid RTP port range")
    if s.rtp_port_max - s.rtp_port_min < 8:
        raise ValidationError("RTP port range too small")
    if s.options_interval < 5:
        raise ValidationError("OPTIONS interval must be at least 5 seconds")
    if s.options_max_failures < 1:
        raise ValidationError("OPTIONS failure threshold must be at least 1")
    if s.phone_min_expires < 10 or s.phone_max_expires < s.phone_min_expires:
        raise ValidationError("Invalid phone registration expiry limits")
    if s.rc_register_expires < 60:
        raise ValidationError("RingCentral registration expiry must be at least 60 seconds")
    for ipf in ("lan_ip", "public_ip"):
        v = getattr(s, ipf)
        if v:
            try:
                socket.inet_aton(v)
            except OSError:
                raise ValidationError(f"{ipf} must be an IPv4 address") from None


class ConfigStore:
    def __init__(self, path: str | None = None):
        self.path = path or os.path.join(DATA_DIR, "config.json")
        self.settings = Settings()
        self.endpoints: list[Endpoint] = []

    def load(self):
        if os.path.exists(self.path):
            with open(self.path) as f:
                data = json.load(f)
            self.settings = _from_dict(Settings, data.get("settings", {}))
            self.endpoints = [_from_dict(Endpoint, e) for e in data.get("endpoints", [])]
        if not self.settings.admin_password_hash:
            self.settings.admin_password_hash = hash_password(
                os.environ.get("ADMIN_PASSWORD", "admin"))
            self.save()

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        data = {
            "settings": dataclasses.asdict(self.settings),
            "endpoints": [dataclasses.asdict(e) for e in self.endpoints],
        }
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)

    def get(self, ep_id: str) -> Endpoint | None:
        return next((e for e in self.endpoints if e.id == ep_id), None)

    @staticmethod
    def endpoint_from_dict(d: dict, existing: Endpoint | None = None) -> Endpoint:
        base = dataclasses.asdict(existing) if existing else {}
        for k, v in d.items():
            if k in SECRET_FIELDS and existing is not None and (v is None or v == ""):
                continue  # blank secret on edit = keep current value
            base[k] = v
        if existing is not None:
            base["id"] = existing.id
        return _from_dict(Endpoint, base)

    @staticmethod
    def settings_from_dict(d: dict, existing: Settings) -> Settings:
        base = dataclasses.asdict(existing)
        for k, v in d.items():
            if k in ("admin_password_hash",):
                continue
            base[k] = v
        return _from_dict(Settings, base)

    def using_default_password(self) -> bool:
        return check_password("admin", self.settings.admin_password_hash)
