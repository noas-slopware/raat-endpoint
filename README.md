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

Status: protocol notes only, no endpoint yet. A capture during playback is still needed for the
stream setup, buffering and clock details (see the open questions in `RAAT-PROTOCOL.md`).
