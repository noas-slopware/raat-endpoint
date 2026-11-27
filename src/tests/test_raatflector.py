#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""End-to-end tests for RAATflector (server + multiple clients) and PipeWire discovery."""
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

RAAT_SERVICE_ID = "d7634b85-8190-470f-aa51-6cb5538dc1b9"


def sood_pack(kind, kv):
    out = bytearray(b"SOOD\x02" + kind.encode("ascii"))
    for k, v in kv.items():
        kb = k.encode("utf-8")
        out.append(len(kb))
        out.extend(kb)
        if v is None:
            out.extend(b"\xff\xff")
        else:
            vb = v.encode("utf-8")
            out.extend(struct.pack(">H", len(vb)))
            out.extend(vb)
    return bytes(out)


def sood_unpack(pkt):
    assert pkt[:5] == b"SOOD\x02", f"bad header: {pkt[:6]!r}"
    kind = chr(pkt[5])
    off = 6
    kv = {}
    while off < len(pkt):
        kl = pkt[off]
        off += 1
        k = pkt[off : off + kl].decode("utf-8")
        off += kl
        vl = struct.unpack(">H", pkt[off : off + 2])[0]
        off += 2
        if vl == 0xFFFF:
            kv[k] = None
        else:
            kv[k] = pkt[off : off + vl].decode("utf-8")
            off += vl
    return kind, kv


def wait_ready(proc, pattern, timeout=5.0):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError(f"process exited early: {proc.stderr.read()}")
        m = re.match(pattern, line.strip())
        if m:
            return m
    raise TimeoutError("timed out waiting for READY")


def test_raatflector(ep_bin, rf_bin):
    print("== RAATflector (1 server + 2 clients + token auth)")
    with tempfile.TemporaryDirectory() as tmp:
        srv = subprocess.Popen(
            [
                rf_bin,
                "--bind", "127.0.0.1",
                "--port", "0",
                "--sood-bind", "127.0.0.1",
                "--sood-port", "0",
                "--no-multicast",
                "--core-ip", "127.0.0.1",
                "--token", "secret123",
                "-v",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        clients = []
        try:
            m = wait_ready(srv, r"READY listen_port=(\d+) sood_port=(\d+)")
            rf_port, rf_sood_port = int(m.group(1)), int(m.group(2))

            # Start 2 endpoints connected to the reflector
            ep_ports = []
            for i in range(2):
                d = os.path.join(tmp, f"ep{i}")
                p = subprocess.Popen(
                    [
                        ep_bin,
                        "-d", d,
                        "-b", "127.0.0.1",
                        "-p", "0",
                        "--sood-port", "0",
                        "--no-multicast",
                        "--name", f"vpn-client-{i}",
                        "--raatflector", f"127.0.0.1:{rf_port}",
                        "--raatflector-token", "secret123",
                        "-v",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                clients.append(p)
                cm = wait_ready(p, r"READY manager_port=(\d+) sood_port=(\d+)")
                ep_ports.append(int(cm.group(1)))

            # Give clients a moment to finish HELLO handshake
            time.sleep(0.25)

            # Fake Core UDP socket: send SOOD Q to reflector's SOOD port
            core = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            core.bind(("127.0.0.1", 0))
            core_port = core.getsockname()[1]
            core.settimeout(2.0)

            q = sood_pack(
                "Q",
                {
                    "service_id": RAAT_SERVICE_ID,
                    "_tid": "11111111-2222-4333-8444-555555555555",
                    "_replyaddr": "192.0.2.99",  # should be overridden by --core-ip 127.0.0.1
                    "_replyport": str(core_port),
                },
            )
            core.sendto(q, ("127.0.0.1", rf_sood_port))

            got = {}
            for _ in range(2):
                data, _ = core.recvfrom(2048)
                kind, kv = sood_unpack(data)
                assert kind == "R", f"expected R, got {kind}"
                assert kv.get("_tid") == "11111111-2222-4333-8444-555555555555"
                assert kv.get("service_id") == RAAT_SERVICE_ID
                got[kv["machine_name"]] = int(kv["tcp_port"])

            assert got == {"vpn-client-0": ep_ports[0], "vpn-client-1": ep_ports[1]}, got
            print("  ok   both VPN clients answered reflected SOOD query directly to Core")
            core.close()
        finally:
            for p in clients:
                p.terminate()
                p.wait(timeout=3)
            srv.terminate()
            srv.wait(timeout=3)


def ll_send(sock, ftype, rid, body):
    jb = json.dumps(body).encode("utf-8")
    hdr = struct.pack(">III", 12 + len(jb), ftype, rid)
    sock.sendall(hdr + jb)


def ll_recv(sock):
    hdr = b""
    while len(hdr) < 8:
        chunk = sock.recv(8 - len(hdr))
        if not chunk:
            raise EOFError("closed")
        hdr += chunk
    total, ftype = struct.unpack(">II", hdr)
    body = b""
    while len(body) < total - 8:
        body += sock.recv(total - 8 - len(body))
    rid = struct.unpack(">I", body[:4])[0]
    final = body[4]
    return ftype, rid, final, json.loads(body[5:].decode("utf-8")) if len(body) > 5 else {}


def test_pipewire_discovery(ep_bin):
    xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    if not os.path.exists(os.path.join(xdg, "pipewire-0")):
        print("== PipeWire discovery (skipped: no pipewire-0 socket)")
        return
    print("== PipeWire discovery (live daemon)")
    with tempfile.TemporaryDirectory() as tmp:
        p = subprocess.Popen(
            [
                ep_bin,
                "-d", tmp,
                "-b", "127.0.0.1",
                "-p", "0",
                "--no-sood",
                "--pipewire",
                "-v",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            m = wait_ready(p, r"READY manager_port=(\d+) sood_port=(\d+)")
            mport = int(m.group(1))
            s = socket.create_connection(("127.0.0.1", mport), timeout=2.0)
            s.settimeout(2.0)
            ll_send(s, 0x80000001, 1, {"request": "enumerate_devices", "subscription_id": "1"})
            _, _, _, r1 = ll_recv(s)
            assert r1.get("status") == "Success", r1
            devs = r1.get("devices", [])
            ids = [d["device_id"] for d in devs]
            names = [d["name"] for d in devs]
            assert "pw:default" in ids, f"missing pw:default in {ids}"
            print(f"  ok   enumerated {len(devs)} PipeWire device(s): {names}")
            s.close()
        finally:
            p.terminate()
            p.wait(timeout=3)


if __name__ == "__main__":
    ep = sys.argv[1] if len(sys.argv) > 1 else "build/host/raat-endpoint"
    rf = sys.argv[2] if len(sys.argv) > 2 else "build/host/raatflector"
    test_raatflector(ep, rf)
    test_pipewire_discovery(ep)
    print("ALL NEW FEATURE TESTS PASSED")
