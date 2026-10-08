# RC UDP Proxy

A SIP back-to-back user agent (B2BUA) that lets **UDP-only SIP phones** use
**RingCentral**, which only accepts SIP over **TCP** or **TLS 1.2+**.

```
 UDP SIP phones (LAN)              this proxy (Docker)                      RingCentral
 ───────────────────      ─────────────────────────────────────      ─────────────────────
  phone A ──UDP 5060──▶  │ phone registrar ─┐                    │ ─TLS/TCP conn #1──▶ sipXX.ringcentral.com
  phone B ──UDP 5060──▶  │ (digest auth)    ├─ per-endpoint RC   │ ─TLS/TCP conn #2──▶
                         │ OPTIONS monitor ─┘   registration     │
  RTP ◀────────────────▶ │ RTP relay (RTP ⇄ RTP/SRTP)            │ ◀──────────RTP/SRTP──▶ media servers
```

## How it works

* Each **endpoint** pairs a phone with one RingCentral device. The endpoint holds:
  * the **phone credentials** that the UDP phone uses to register to the proxy.
  * the **RingCentral device credentials**: SIP domain, outbound proxy, user name,
    password and Authorization ID.
* When the phone **registers** (digest-authenticated), the proxy opens a **dedicated
  TCP or TLS connection** for that endpoint and registers to RingCentral on the phone's
  behalf. The phone gets `200 OK` only after RingCentral accepts the registration. If
  RingCentral rejects it, the phone gets `503` and the reason is shown in the UI.
* The proxy pings each registered phone with **SIP OPTIONS** (every 30 s by default).
  The phone is marked offline when any of these happens:
  * it misses the configured number of OPTIONS in a row (3 by default),
  * its registration expires,
  * it unregisters.

  When the phone goes offline, the proxy drops its active calls, **unregisters from
  RingCentral** and closes that endpoint's connection.
* **Calls** are bridged in both directions as two independent SIP dialogs (B2BUA). The
  proxy answers RingCentral's digest challenges (e.g. `407` on INVITE) itself. Supported
  in-call features:
  * Hold/resume (re-INVITE/UPDATE).
  * DTMF (RFC 2833 in RTP, or SIP INFO).
  * Blind and attended transfer (REFER, including `Replaces` translation).
  * CANCEL, busy and other failure responses.
  * Unsolicited voicemail MWI NOTIFYs are passed to the phone.
* **RTP is always relayed** through the proxy. Each call gets its own UDP port pairs
  on the phone side and the RingCentral side. Toward RingCentral the media can
  optionally be **SRTP** (SDES, AES_CM_128_HMAC_SHA1_80/32). The phone side is always
  plain RTP. If RingCentral offers SRTP on an incoming call, the proxy accepts it
  automatically.

## NAT / network

The intended setup is a host on a private LAN, with phones on the same LAN and
RingCentral reached **outbound through a NAT firewall**:

* **Signaling:** each endpoint keeps its own long-lived outbound TCP/TLS connection
  with CRLF keep-alives every 30 s, plus TCP keepalive. RingCentral sends incoming
  calls back over that same connection, so **no inbound port forward is needed for SIP**.
* **Public address:** the proxy learns its public (NAT) IP from the `received=`
  parameter RingCentral puts in REGISTER responses. It advertises that IP in SDP sent
  to RingCentral. You can override it with *Settings → Public IP*.
* **Media:** RTP uses symmetric latching. The proxy sends media from the same port
  where it expects to receive it, which opens the NAT pinhole, and it accepts return
  media from the address RingCentral signalled. With most firewalls this works with no
  inbound rules. If audio is one-way (RingCentral → phone silent), forward the RTP
  range (default **UDP 20000–20999**) to this host, or allow it in the firewall.
* **Outbound access required:** TCP to the RingCentral outbound proxy host and port,
  and UDP to RingCentral media servers.
* **Phones ↔ proxy:** plain UDP on the LAN. Phones send to `<host-ip>:5060`.

The container uses `network_mode: host`, so Docker adds no NAT layer and no large
UDP port range has to be published.

## Install and run

Requirements: Docker Engine with the compose plugin.

```bash
git clone git@github.com:thedayowl/RC-Udp-Proxy.git
cd RC-Udp-Proxy
ADMIN_PASSWORD='choose-a-password' docker compose up -d --build
docker compose logs -f
```

* Web UI: `http://<host-ip>:8080/` (user `admin`). `ADMIN_PASSWORD` only sets the
  password on first start. After that, change it under *Settings*. If it isn't set,
  the password is `admin` and the UI shows a warning until you change it.
* Configuration is stored in `./data/config.json` with mode 0600. It contains SIP
  passwords, so protect and back up this directory.
* Upgrade: `git pull && docker compose up -d --build`.

## Configure an endpoint

1. In the RingCentral admin portal, set the device up as an "Existing phone / other
   phone" and open its **Set Up and Provision** page to get:
   * SIP domain (e.g. `sip.ringcentral.com`)
   * Outbound proxy (`host:port`; use the TLS or TCP value matching the transport you choose)
   * User name, Password, Authorization ID
2. In the proxy UI, choose **Add endpoint** and enter:
   * a phone username and password (choose your own; *Generate password* helps),
   * the RingCentral values above,
   * the transport (TLS recommended) and the media encryption toward RingCentral.
     If RingCentral requires secure voice for the device, select **SRTP**.
3. Configure the phone:

   | Phone setting          | Value                                   |
   |------------------------|-----------------------------------------|
   | SIP server / registrar | `<host-ip>` port `5060`, transport UDP  |
   | Outbound proxy         | (none, or the same as SIP server)       |
   | User / Auth user       | the endpoint's *phone username*         |
   | Password               | the endpoint's *phone password*         |
   | Registration expiry    | anything ≥ 60 s (capped at 300 s)       |

   The endpoint status shows the phone as **online** and RingCentral as
   **registered** within a few seconds.

Dial numbers the same way you would on a RingCentral phone (extensions, 10/11-digit
numbers, E.164). The dialed user part is passed to RingCentral as is.

## Settings

| Setting | Default | Notes |
|---|---|---|
| LAN IP advertised to phones | auto | Used in SDP/Contact for phones |
| Public IP for RingCentral media | auto | Learned from RingCentral; set it if you have a static public IP |
| SIP UDP port | 5060 | Port phones register to |
| RTP port range | 20000–20999 | 4 ports per call |
| Max / min phone registration expiry | 300 / 60 s | |
| OPTIONS interval / missed before offline | 30 s / 3 | Phone reachability check |
| RingCentral registration expiry | 600 s | Refreshed at ~80 % |
| Verify TLS certificates | on | |
| Log level / full SIP trace | INFO / off | Logs are on the *Logs* tab and in `docker compose logs` |

## Troubleshooting

* **Phone gets 403:** wrong phone username or password.
* **Phone gets 503 "RingCentral Registration Failed":** RingCentral rejected the
  credentials or the connection failed. The endpoint row shows the error, e.g.
  `403 Forbidden`, a timeout, or a TLS error. Check the outbound proxy host and port
  against the selected transport.
* **One-way audio:** see [NAT / network](#nat--network). The *Calls* tab shows packet
  counters for each direction.
* **SRTP errors on the Calls tab:** switch the endpoint's media encryption setting.
* Turn on **Log full SIP messages** in Settings to see every SIP message.

## Limitations

* IPv4 only.
* Phones must use UDP. The phone leg is plain RTP; phone-side SRTP isn't supported.
* Reliable provisional responses (100rel/PRACK) are not used. Session timers are not
  enforced, but refreshes from either side are passed through.
* Phone SUBSCRIBE requests (BLF/MWI) are answered with `489`. RingCentral's
  unsolicited MWI NOTIFYs are forwarded.
* The web UI uses HTTP Basic auth without TLS. Expose it only on a trusted network,
  or put a TLS reverse proxy in front of it.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest          # end-to-end tests against a fake RingCentral + fake phone
RCPROXY_DATA=./data .venv/bin/python -m rcproxy   # run without Docker (needs UDP 5060 free)
```

Code layout:

| Path | Purpose |
|---|---|
| `rcproxy/sip/message.py` | SIP parser/serializer, URI/Via/name-addr helpers, TCP stream framing |
| `rcproxy/sip/transport.py` | UDP transport, TCP/TLS connection, client/server transactions and retransmissions |
| `rcproxy/sip/digest.py` | Digest auth (server side for phones, client side for RingCentral) |
| `rcproxy/sip/sdp.py` | SDP model |
| `rcproxy/endpoint.py` | Per-endpoint state: phone registration and OPTIONS monitoring, RingCentral registration supervisor |
| `rcproxy/call.py` | B2BUA call and dialog logic |
| `rcproxy/media.py` | RTP/RTCP relay, SDP rewriting, SRTP (via `pylibsrtp`) |
| `rcproxy/core.py` | Request routing, phone REGISTER/INVITE authentication, endpoint management |
| `rcproxy/web.py`, `rcproxy/static/index.html` | REST API and web UI |
| `tests/` | Integration tests (fake RingCentral TCP/TLS server, fake UDP phone) |
