"""Web UI / REST API (aiohttp)."""
from __future__ import annotations

import asyncio
import base64
import dataclasses
import logging
import os

from aiohttp import web

from .config import (SECRET_FIELDS, ConfigStore, ValidationError, check_password, hash_password,
                     validate_endpoint, validate_settings)
from .logsetup import ring

log = logging.getLogger("rcproxy.web")
STATIC = os.path.join(os.path.dirname(__file__), "static")


def _endpoint_json(ep, reveal=False):
    d = dataclasses.asdict(ep)
    for f in SECRET_FIELDS:
        if not reveal:
            d[f] = ""
        d[f"has_{f}"] = bool(getattr(ep, f))
    return d


def _settings_json(s):
    d = dataclasses.asdict(s)
    d.pop("admin_password_hash", None)
    return d


@web.middleware
async def auth_middleware(request: web.Request, handler):
    core = request.app["core"]
    s = core.settings
    hdr = request.headers.get("Authorization", "")
    ok = False
    if hdr.startswith("Basic "):
        try:
            user, _, pw = base64.b64decode(hdr[6:]).decode().partition(":")
            ok = user == s.admin_user and check_password(pw, s.admin_password_hash)
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            await asyncio.sleep(1)
    if not ok:
        return web.Response(status=401, text="Authentication required",
                            headers={"WWW-Authenticate": 'Basic realm="RC UDP Proxy"'})
    if request.method not in ("GET", "HEAD") and request.headers.get("X-Requested-With") != "rcproxy":
        return web.json_response({"error": "missing X-Requested-With header"}, status=403)
    try:
        return await handler(request)
    except ValidationError as e:
        return web.json_response({"error": str(e)}, status=400)
    except (ValueError, KeyError, TypeError) as e:
        return web.json_response({"error": f"invalid request: {e}"}, status=400)


async def index(request):
    return web.FileResponse(os.path.join(STATIC, "index.html"),
                            headers={"Cache-Control": "no-store"})


async def get_status(request):
    return web.json_response(request.app["core"].status())


async def list_endpoints(request):
    core = request.app["core"]
    return web.json_response([_endpoint_json(e) for e in core.store.endpoints])


async def get_endpoint(request):
    core = request.app["core"]
    ep = core.store.get(request.match_info["id"])
    if ep is None:
        raise web.HTTPNotFound()
    return web.json_response(_endpoint_json(ep, reveal=request.query.get("reveal") == "1"))


async def create_endpoint(request):
    core = request.app["core"]
    data = await request.json()
    data.pop("id", None)
    ep = ConfigStore.endpoint_from_dict(data)
    validate_endpoint(ep, core.store.endpoints)
    await core.add_endpoint(ep)
    log.info("endpoint '%s' added", ep.name or ep.phone_username)
    return web.json_response(_endpoint_json(ep), status=201)


async def update_endpoint(request):
    core = request.app["core"]
    existing = core.store.get(request.match_info["id"])
    if existing is None:
        raise web.HTTPNotFound()
    data = await request.json()
    ep = ConfigStore.endpoint_from_dict(data, existing)
    validate_endpoint(ep, core.store.endpoints)
    await core.update_endpoint(ep)
    log.info("endpoint '%s' updated", ep.name or ep.phone_username)
    return web.json_response(_endpoint_json(ep))


async def delete_endpoint(request):
    core = request.app["core"]
    ep = core.store.get(request.match_info["id"])
    if ep is None:
        raise web.HTTPNotFound()
    await core.delete_endpoint(ep.id)
    log.info("endpoint '%s' deleted", ep.name or ep.phone_username)
    return web.json_response({"ok": True})


async def reregister(request):
    await request.app["core"].reregister(request.match_info["id"])
    return web.json_response({"ok": True})


async def get_settings(request):
    return web.json_response(_settings_json(request.app["core"].settings))


async def put_settings(request):
    core = request.app["core"]
    data = await request.json()
    new = ConfigStore.settings_from_dict(data, core.settings)
    validate_settings(new)
    await core.update_settings(new)
    log.info("settings updated")
    return web.json_response(_settings_json(new))


async def change_password(request):
    core = request.app["core"]
    data = await request.json()
    if not check_password(data.get("current", ""), core.settings.admin_password_hash):
        raise ValidationError("Current password is incorrect")
    new = data.get("new", "")
    if len(new) < 8:
        raise ValidationError("New password must be at least 8 characters")
    core.settings.admin_password_hash = hash_password(new)
    core.store.save()
    log.info("admin password changed")
    return web.json_response({"ok": True})


async def get_logs(request):
    since = int(request.query.get("since", "0"))
    return web.json_response(ring.since(since))


async def start_web(core, port: int) -> web.AppRunner:
    app = web.Application(middlewares=[auth_middleware])
    app["core"] = core
    app.router.add_get("/", index)
    app.router.add_get("/api/status", get_status)
    app.router.add_get("/api/endpoints", list_endpoints)
    app.router.add_post("/api/endpoints", create_endpoint)
    app.router.add_get("/api/endpoints/{id}", get_endpoint)
    app.router.add_put("/api/endpoints/{id}", update_endpoint)
    app.router.add_delete("/api/endpoints/{id}", delete_endpoint)
    app.router.add_post("/api/endpoints/{id}/reregister", reregister)
    app.router.add_get("/api/settings", get_settings)
    app.router.add_put("/api/settings", put_settings)
    app.router.add_post("/api/password", change_password)
    app.router.add_get("/api/logs", get_logs)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    return runner
