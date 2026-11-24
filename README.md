# raat-endpoint

Notes and tools for a native RAAT endpoint (Roon Ready audio transport) on small Linux boxes, to
replace the .NET RoonBridge. The first target is the Gustard R26 streamer
(see [r26-mainline](https://github.com/noas-slopware/r26-mainline)).

Roon Labs (Brian Luczkiewicz) has said reverse engineering for interoperability is fine as long as no
encryption is broken. Nothing here breaks any: script signing is a public-key check that an endpoint
performs, and no key, licence or DRM material is involved. No Roon code, decompiled code or captured
scripts are in this repository; `RAAT-PROTOCOL.md` describes behaviour and cites where it was found.

| Path | What |
|---|---|
| `RAAT-PROTOCOL.md` | the protocol as far as it is known: discovery, the manager JSON-RPC, script loading, the session and audio paths, open questions |
| `tools/r26cap.c` | tiny static pcap capture (AF_PACKET) for boxes without tcpdump: TCP to and from one peer, both directions |
| `tools/ll_decode.py` | reassembles the TCP streams of a capture and decodes the RAAT frames to JSON lines |
| `src/` | the endpoint in C: SOOD responder, manager JSON-RPC, per-device LL server, Lua 5.3 host for the Core's scripts with the `raat`/`buffer`/`stream`/`uv` surface, ALSA output thread. `make`, `make armhf`, `make test` |

Status: the endpoint is written and passes a replay of the captured handshake and of a playback
capture (play, seek, pause, resume, next track at 44.1 kHz), including a bit-for-bit check of what
the output plays (`src/tests/replay.py`, reads the captures from outside the repo). Not run against
a Core or a DAC yet. Still unseen: format changes, high rates, grouped zones (`sync`), gapless
track ends.

## Installing in place of RoonBridge

The endpoint takes over RoonBridge's zone only if it reuses RoonBridge's identity (the Core keys an
enabled device on the server's `unique_id` and `machine_id` plus the device config's `unique_id`):

```sh
install -m 755 raat-endpoint /usr/local/bin/raat-endpoint
install -d /var/lib/raat-endpoint/Settings
cp /var/roon/RAATServer/Settings/unique_id /var/lib/raat-endpoint/Settings/unique_id
# RoonBridge's machine_id, as its log prints it (not /etc/machine-id)
grep -h 'machine_id   =' /var/roon/RAATServer/Logs/RAATServer_log.txt | tail -1 | sed 's/.*= //' \
    | tr -d '\r\n' > /var/lib/raat-endpoint/Settings/machine_id
# the device config (RoonBridge names it device_<hash>.json; ours is device_<alsa id>.json)
cp /var/roon/RAATServer/Settings/device_<hash>.json /var/lib/raat-endpoint/Settings/device_hw_CARD_G20_DEV_0.json
install -m 644 packaging/raat-endpoint.service /etc/systemd/system/
systemctl disable --now roonbridge
systemctl daemon-reload && systemctl enable --now raat-endpoint
```

Going back is `systemctl disable --now raat-endpoint && systemctl enable --now roonbridge`.
