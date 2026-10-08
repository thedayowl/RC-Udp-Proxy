import asyncio
import os
import socket
import subprocess
import ssl

import pytest

from rcproxy import logsetup
from rcproxy.config import ConfigStore, Endpoint
from rcproxy.core import Core
from rcproxy.sip.sdp import Sdp

from .fakes import (FakePhone, FakeRingCentral, Media, crypto_key, is_req, is_resp, rtp_packet,
                    sdp_body, sdp_target, srtp_pair)

pytestmark = pytest.mark.asyncio(loop_scope="function")

PHONE_USER, PHONE_PW = "frontdesk", "phonepass1"
RC_USER, RC_AUTH, RC_PW = "16505551234", "802123456789", "rcsecret"


def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Env:
    pass


async def make_env(tmp_path, transport="tcp", srtp="off", tls_ctx=None):
    env = Env()
    env.rc = await FakeRingCentral(RC_AUTH, RC_PW, tls_ctx=tls_ctx).start()
    store = ConfigStore(str(tmp_path / "config.json"))
    store.load()
    s = store.settings
    s.lan_ip = "127.0.0.1"
    s.public_ip = "127.0.0.1"
    s.sip_port = free_udp_port()
    s.rtp_port_min, s.rtp_port_max = 31000, 31400
    s.options_interval = 1
    s.options_max_failures = 2
    s.phone_min_expires = 10
    s.tls_verify = False
    s.log_level = "DEBUG"
    s.sip_trace = bool(os.environ.get("SIP_TRACE"))
    store.endpoints = [Endpoint(name="Front desk", phone_username=PHONE_USER, phone_password=PHONE_PW,
                                rc_sip_domain="sip.ringcentral.com",
                                rc_outbound_proxy=f"127.0.0.1:{env.rc.port}", rc_username=RC_USER,
                                rc_password=RC_PW, rc_auth_id=RC_AUTH, rc_transport=transport,
                                srtp=srtp)]
    logsetup.setup(s)
    env.core = Core(store)
    await env.core.start()
    env.ep = next(iter(env.core.endpoints.values()))
    env.phone = await FakePhone(PHONE_USER, PHONE_PW, ("127.0.0.1", s.sip_port)).start()
    return env


async def close_env(env):
    env.phone.close()
    await env.core.stop()
    await env.rc.stop()


@pytest.fixture
async def env(tmp_path):
    e = await make_env(tmp_path)
    yield e
    await close_env(e)


async def register(env):
    r = await env.phone.register(60)
    assert r.status == 200, (r.status, r.reason)
    return r


async def test_registration_mirrors_to_ringcentral(env):
    r = await register(env)
    assert "expires=60" in r.get("Contact")
    assert env.ep.rc_state == "registered"
    assert len(env.rc.registrations) == 1
    contact = next(iter(env.rc.registrations))
    assert RC_USER in contact and "transport=tcp" in contact
    # public address learned from Via received=
    assert env.ep.learned_public_ip == "203.0.113.7"
    st = env.core.status()["endpoints"][env.ep.cfg.id]
    assert st["phone"]["online"] and st["rc"]["state"] == "registered"


async def test_wrong_phone_password_rejected(env):
    r = await env.phone.register(60, password="wrong")
    assert r.status == 403
    assert env.ep.rc_state == "idle"
    assert not env.rc.registrations


async def test_bad_rc_credentials_reject_phone(tmp_path):
    e = await make_env(tmp_path)
    try:
        e.rc.password = "different"
        r = await e.phone.register(60)
        assert r.status == 503
        assert "401" in e.ep.rc_error
        assert not e.ep.phone_online
    finally:
        await close_env(e)


async def test_phone_unregister_drops_rc(env):
    await register(env)
    r = await env.phone.register(0)
    assert r.status == 200
    for _ in range(50):
        if env.rc.closed_conns:
            break
        await asyncio.sleep(0.1)
    assert env.rc.register_log[-1][1] == 0
    assert not env.rc.registrations
    assert env.ep.rc_state == "idle"
    assert env.rc.closed_conns == 1


async def test_options_failure_drops_rc(env):
    await register(env)
    for _ in range(40):
        if env.phone.options_seen:
            break
        await asyncio.sleep(0.1)
    assert env.phone.options_seen >= 1
    assert env.ep.phone_online
    env.phone.alive = False
    for _ in range(150):
        if not env.rc.registrations and env.rc.closed_conns:
            break
        await asyncio.sleep(0.1)
    assert not env.ep.phone_online
    assert env.ep.phone_offline_reason == "not responding to OPTIONS"
    assert env.rc.register_log[-1][1] == 0
    assert env.ep.rc_state == "idle"


async def _outbound_call(env, phone_media, rc_media, rc_answer_body=None):
    await register(env)
    inv, callid, tag = await env.phone.invite("18005551212", sdp_body("127.0.0.1", phone_media.port))
    rc_inv = await env.rc.q.get(is_req("INVITE"))
    assert rc_inv.uri == "sip:18005551212@sip.ringcentral.com"
    assert rc_inv.get("Proxy-Authorization")
    assert RC_USER in rc_inv.get("From")
    env.rc.respond(rc_inv, 100)
    env.rc.respond(rc_inv, 180)
    r = await env.phone.q.get(is_resp("INVITE", 180))
    env.rc.respond(rc_inv, 200, rc_answer_body or sdp_body("127.0.0.1", rc_media.port))
    ok = await env.phone.q.get(is_resp("INVITE", 200))
    rc_ack = await env.rc.q.get(is_req("ACK"))
    assert rc_ack.call_id == rc_inv.call_id
    env.phone.send(env.phone.ack_for(inv, ok))
    return inv, ok, rc_inv


async def test_outbound_call_with_media(env):
    pm, rm = await Media.open(), await Media.open()
    inv, ok, rc_inv = await _outbound_call(env, pm, rm)
    # SDP towards RC uses the configured public IP and a relay port, not the phone's
    rc_ip, rc_side_port = sdp_target(rc_inv.body)
    assert (rc_ip, rc_side_port) != ("127.0.0.1", pm.port)
    ph_ip, ph_side_port = sdp_target(ok.body)
    assert ph_ip == "127.0.0.1" and ph_side_port != rm.port
    # phone -> RC
    pm.send(rtp_packet(1), (ph_ip, ph_side_port))
    data, _ = await rm.recv()
    assert data == rtp_packet(1)
    # RC -> phone
    rm.send(rtp_packet(7, 0x9999), (rc_ip, rc_side_port))
    data, _ = await pm.recv()
    assert data == rtp_packet(7, 0x9999)
    assert len(env.core.calls) == 1
    call = next(iter(env.core.calls.values()))
    assert call.state == "confirmed"
    # phone hangs up
    bye = env.phone.in_dialog("BYE", inv, ok)
    env.phone.send(bye)
    r = await env.phone.q.get(is_resp("BYE"))
    assert r.status == 200
    rc_bye = await env.rc.q.get(is_req("BYE"))
    assert rc_bye.call_id == rc_inv.call_id
    env.rc.respond(rc_bye, 200)
    await asyncio.sleep(0.1)
    assert not env.core.calls
    assert env.core.history[0]["end_reason"] == "BYE from phone"
    pm.close(), rm.close()


async def test_outbound_hold_reinvite(env):
    pm, rm = await Media.open(), await Media.open()
    inv, ok, rc_inv = await _outbound_call(env, pm, rm)
    rc_port_before = sdp_target(rc_inv.body)[1]
    reinv = env.phone.in_dialog("INVITE", inv, ok)
    reinv.add("Content-Type", "application/sdp")
    reinv.body = sdp_body("127.0.0.1", pm.port).replace(b"a=sendrecv", b"a=sendonly").replace(b"o=test 1 1", b"o=test 1 2")
    env.phone.send(reinv)
    rc_re = await env.rc.q.get(is_req("INVITE"))
    assert b"a=sendonly" in rc_re.body
    assert sdp_target(rc_re.body)[1] == rc_port_before
    o_before = Sdp.parse(rc_inv.body).origin[2]
    assert int(Sdp.parse(rc_re.body).origin[2]) == int(o_before) + 1
    env.rc.respond(rc_re, 200, sdp_body("127.0.0.1", rm.port).replace(b"a=sendrecv", b"a=recvonly"))
    r = await env.phone.q.get(is_resp("INVITE", 200))
    assert b"a=recvonly" in r.body
    await env.rc.q.get(is_req("ACK"))
    pm.close(), rm.close()


async def test_rc_bye_on_outbound(env):
    pm, rm = await Media.open(), await Media.open()
    inv, ok, rc_inv = await _outbound_call(env, pm, rm)
    # RC sends BYE in the dialog it accepted (RC was UAS)
    from rcproxy.sip.message import SipMessage, gen_branch
    bye = SipMessage.request("BYE", rc_inv.get_list("Contact")[0].strip("<>"))
    bye.add("Via", f"SIP/2.0/TCP 127.0.0.1:{env.rc.port};branch={gen_branch()}")
    bye.add("From", f"<sip:18005551212@sip.ringcentral.com>;tag=rctag")
    bye.add("To", rc_inv.get("From"))
    bye.add("Call-ID", rc_inv.call_id)
    bye.add("CSeq", "1 BYE")
    env.rc.send(bye)
    r = await env.rc.q.get(is_resp("BYE"))
    assert r.status == 200
    ph_bye = await env.phone.q.get(is_req("BYE"))
    assert ph_bye.call_id == inv.call_id
    pm.close(), rm.close()


async def _inbound_call(env, pm, rm):
    await register(env)
    inv = env.rc.new_invite(RC_USER, sdp_body("127.0.0.1", rm.port))
    env.rc.send(inv)
    trying = await env.rc.q.get(is_resp("INVITE", 100))
    ph_inv = await env.phone.q.get(is_req("INVITE"))
    assert "Caller Name" in ph_inv.get("From") and "+16505550100" in ph_inv.get("From")
    assert ph_inv.uri.startswith(f"sip:{PHONE_USER}@127.0.0.1:{env.phone.addr[1]}")
    env.phone.answer(ph_inv, 180)
    ringing = await env.rc.q.get(is_resp("INVITE", 180))
    ph_ok = env.phone.answer(ph_inv, 200, sdp_body("127.0.0.1", pm.port))
    rc_ok = await env.rc.q.get(is_resp("INVITE", 200))
    ph_ack = await env.phone.q.get(is_req("ACK"))
    assert ph_ack.call_id == ph_inv.call_id
    ack = env.rc.in_dialog("ACK", inv, rc_ok, cseq=101)
    env.rc.send(ack)
    return inv, rc_ok, ph_inv, ph_ok


async def test_inbound_call_with_media(env):
    pm, rm = await Media.open(), await Media.open()
    inv, rc_ok, ph_inv, ph_ok = await _inbound_call(env, pm, rm)
    ph_ip, ph_port = sdp_target(ph_inv.body)
    rc_ip, rc_port = sdp_target(rc_ok.body)
    rm.send(rtp_packet(3), (rc_ip, rc_port))
    assert (await pm.recv())[0] == rtp_packet(3)
    pm.send(rtp_packet(4), (ph_ip, ph_port))
    assert (await rm.recv())[0] == rtp_packet(4)
    # RC hangs up
    bye = env.rc.in_dialog("BYE", inv, rc_ok, cseq=102)
    env.rc.send(bye)
    assert (await env.rc.q.get(is_resp("BYE"))).status == 200
    ph_bye = await env.phone.q.get(is_req("BYE"))
    assert ph_bye.call_id == ph_inv.call_id
    pm.close(), rm.close()


async def test_inbound_call_phone_hangs_up(env):
    pm, rm = await Media.open(), await Media.open()
    inv, rc_ok, ph_inv, ph_ok = await _inbound_call(env, pm, rm)
    bye = env.phone.in_dialog("BYE", ph_inv, ph_ok, uas=True)
    env.phone.send(bye)
    assert (await env.phone.q.get(is_resp("BYE"))).status == 200
    rc_bye = await env.rc.q.get(is_req("BYE"))
    assert rc_bye.call_id == inv.call_id
    assert rc_bye.to_tag == inv.from_tag
    pm.close(), rm.close()


async def test_inbound_cancel(env):
    rm = await Media.open()
    await register(env)
    inv = env.rc.new_invite(RC_USER, sdp_body("127.0.0.1", rm.port))
    env.rc.send(inv)
    ph_inv = await env.phone.q.get(is_req("INVITE"))
    env.phone.answer(ph_inv, 180)
    await env.rc.q.get(is_resp("INVITE", 180))
    from rcproxy.sip.message import SipMessage
    cancel = SipMessage.request("CANCEL", inv.uri)
    cancel.add("Via", inv.get("Via"))
    cancel.add("From", inv.get("From"))
    cancel.add("To", inv.get("To"))
    cancel.add("Call-ID", inv.call_id)
    cancel.add("CSeq", "101 CANCEL")
    env.rc.send(cancel)
    assert (await env.rc.q.get(is_resp("CANCEL"))).status == 200
    assert (await env.rc.q.get(is_resp("INVITE", 487))).status == 487
    ph_cancel = await env.phone.q.get(is_req("CANCEL"))
    assert ph_cancel.call_id == ph_inv.call_id
    rm.close()


async def test_inbound_when_phone_offline(env):
    await register(env)
    env.ep.phone_expires_at = 0  # simulate expiry without waiting
    inv = env.rc.new_invite(RC_USER, sdp_body("127.0.0.1", 40000))
    env.rc.send(inv)
    r = await env.rc.q.get(lambda m: not m.is_request and m.cseq[1] == "INVITE" and m.status >= 200)
    assert r.status == 480


async def test_inbound_busy(env):
    rm = await Media.open()
    await register(env)
    inv = env.rc.new_invite(RC_USER, sdp_body("127.0.0.1", rm.port))
    env.rc.send(inv)
    ph_inv = await env.phone.q.get(is_req("INVITE"))
    env.phone.answer(ph_inv, 486)
    r = await env.rc.q.get(lambda m: not m.is_request and m.cseq[1] == "INVITE" and m.status >= 200)
    assert r.status == 486
    rm.close()


async def test_outbound_srtp(tmp_path):
    env = await make_env(tmp_path, srtp="sdes")
    try:
        pm, rm = await Media.open(), await Media.open()
        await register(env)
        inv, callid, tag = await env.phone.invite("18005551212", sdp_body("127.0.0.1", pm.port))
        rc_inv = await env.rc.q.get(is_req("INVITE"))
        assert "RTP/SAVP" in rc_inv.body.decode()
        t, suite, proxy_key = crypto_key(rc_inv.body, "1")
        rc_key = os.urandom(30)
        import base64
        answer = sdp_body("127.0.0.1", rm.port, proto="RTP/SAVP",
                          extra=[f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{base64.b64encode(rc_key).decode()}"])
        env.rc.respond(rc_inv, 200, answer)
        ok = await env.phone.q.get(is_resp("INVITE", 200))
        assert "RTP/AVP" in ok.body.decode() and b"crypto" not in ok.body
        env.phone.send(env.phone.ack_for(inv, ok))
        await env.rc.q.get(is_req("ACK"))
        rc_tx, rc_rx = srtp_pair(rc_key, proxy_key)
        ph_ip, ph_port = sdp_target(ok.body)
        rc_ip, rc_port = sdp_target(rc_inv.body)
        pm.send(rtp_packet(10), (ph_ip, ph_port))
        data, _ = await rm.recv()
        assert data != rtp_packet(10)
        assert rc_rx.unprotect(data) == rtp_packet(10)
        rm.send(rc_tx.protect(rtp_packet(20, 0x777)), (rc_ip, rc_port))
        data, _ = await pm.recv()
        assert data == rtp_packet(20, 0x777)
        call = next(iter(env.core.calls.values()))
        assert call.media.srtp
        pm.close(), rm.close()
    finally:
        await close_env(env)


async def test_inbound_srtp_offer_from_rc(env):
    import base64
    pm, rm = await Media.open(), await Media.open()
    await register(env)
    rc_key = os.urandom(30)
    body = sdp_body("127.0.0.1", rm.port, proto="RTP/SAVP",
                    extra=[f"a=crypto:3 AES_CM_128_HMAC_SHA1_32 inline:{base64.b64encode(rc_key).decode()}"])
    inv = env.rc.new_invite(RC_USER, body)
    env.rc.send(inv)
    ph_inv = await env.phone.q.get(is_req("INVITE"))
    assert b"crypto" not in ph_inv.body and b"RTP/AVP" in ph_inv.body
    env.phone.answer(ph_inv, 200, sdp_body("127.0.0.1", pm.port))
    rc_ok = await env.rc.q.get(is_resp("INVITE", 200))
    t, suite, proxy_key = crypto_key(rc_ok.body)
    assert t == "3" and suite == "AES_CM_128_HMAC_SHA1_32"
    assert b"RTP/SAVP" in rc_ok.body
    rc_tx, rc_rx = srtp_pair(rc_key, proxy_key, "SRTP_PROFILE_AES128_CM_SHA1_32")
    rc_ip, rc_port = sdp_target(rc_ok.body)
    ph_ip, ph_port = sdp_target(ph_inv.body)
    rm.send(rc_tx.protect(rtp_packet(5)), (rc_ip, rc_port))
    assert (await pm.recv())[0] == rtp_packet(5)
    pm.send(rtp_packet(6), (ph_ip, ph_port))
    assert rc_rx.unprotect((await rm.recv())[0]) == rtp_packet(6)
    pm.close(), rm.close()


async def test_tls_transport(tmp_path):
    certdir = tmp_path / "cert"
    certdir.mkdir()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-keyout", str(certdir / "k.pem"),
                    "-out", str(certdir / "c.pem")], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certdir / "c.pem", certdir / "k.pem")
    env = await make_env(tmp_path, transport="tls", tls_ctx=ctx)
    try:
        await register(env)
        assert env.ep.rc_conn.proto == "TLS"
        assert env.ep.rc_conn.writer.get_extra_info("ssl_object").version() == "TLSv1.2"
        contact = next(iter(env.rc.registrations))
        assert "transport=tls" in contact
    finally:
        await close_env(env)


async def test_rc_connection_loss_reregisters(env):
    await register(env)
    first_closed = env.rc.closed_conns
    env.rc.writer.close()          # RC drops the TCP connection
    for _ in range(100):
        if env.ep.rc_state == "registered" and env.rc.closed_conns > first_closed \
                and len(env.rc.conns) == 2:
            break
        await asyncio.sleep(0.1)
    assert len(env.rc.conns) == 2
    assert env.ep.rc_state == "registered"
