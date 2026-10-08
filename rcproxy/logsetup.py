"""Logging: stdout plus an in-memory ring buffer served to the web UI."""
from __future__ import annotations

import collections
import itertools
import logging
import time

_counter = itertools.count(1)


class RingBufferHandler(logging.Handler):
    def __init__(self, capacity: int = 3000):
        super().__init__()
        self.records: collections.deque = collections.deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord):
        try:
            self.records.append({
                "id": next(_counter),
                "ts": record.created,
                "level": record.levelname,
                "logger": record.name,
                "msg": self.format(record),
            })
        except Exception:  # noqa: BLE001
            self.handleError(record)

    def since(self, last_id: int, limit: int = 500) -> list[dict]:
        out = [r for r in self.records if r["id"] > last_id]
        return out[-limit:]


ring = RingBufferHandler()


def setup(settings):
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    fmt.converter = time.localtime
    root = logging.getLogger()
    root.handlers.clear()
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    ring.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(ring)
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    apply_levels(settings)


def apply_levels(settings):
    level = getattr(logging, (settings.log_level or "INFO").upper(), logging.INFO)
    logging.getLogger().setLevel(level)
    logging.getLogger("rcproxy").setLevel(level)
    trace = logging.getLogger("rcproxy.trace")
    trace.setLevel(logging.DEBUG if settings.sip_trace else logging.WARNING)
    # trace messages must pass the root/handler level when enabled
    if settings.sip_trace and level > logging.DEBUG:
        logging.getLogger().setLevel(logging.DEBUG)
        for name in ("rcproxy.sip", "rcproxy.core", "rcproxy.endpoint", "rcproxy.call",
                     "rcproxy.media", "rcproxy.web", "asyncio", "aiohttp"):
            logging.getLogger(name).setLevel(level)
