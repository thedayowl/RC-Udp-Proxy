import asyncio
import logging
import os
import signal

from . import __version__, logsetup
from .config import ConfigStore
from .core import Core
from .web import start_web

log = logging.getLogger("rcproxy")


async def main():
    store = ConfigStore()
    store.load()
    logsetup.setup(store.settings)
    log.info("RC UDP Proxy %s starting (data: %s)", __version__, store.path)
    core = Core(store)
    await core.start()
    web_port = int(os.environ.get("WEB_PORT", "8080"))
    runner = await start_web(core, web_port)
    log.info("Web UI on http://%s:%s/", core.lan_ip, web_port)
    if store.using_default_password():
        log.warning("Web UI is using the default password 'admin' - change it under Settings")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("shutting down")
    await core.stop()
    await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
