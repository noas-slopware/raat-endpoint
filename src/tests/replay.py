#!/usr/bin/env python3
"""Replay test for raat-endpoint, loopback only.

usage: replay.py [--qemu qemu-arm] <raat-endpoint binary>

1. Manager replay: the Core->endpoint manager frames of capture/ (capture2 has
   none: its manager connection was already open) go to the endpoint; the
   replies must match the endpoint->Core frames of capture2 (c2:5-7).
2. Device replay: the Core->endpoint device frames of capture2 (keepalive,
   four load_script, four session requests) go to the device server; the
   replies must match capture2's endpoint->Core frames.
3. Playback replay: the Core's session requests and audio connections of
   capture3 (play, seek, pause, resume, next track) go to the same session,
   in order, with the waits shortened and min_offset computed the way the
   Core did (last RAATCLKR delay + 20 ms). Replies must match capture3's
   (frames lost by the capture tool are accounted for byte by byte), the
   clock must behave as captured, and the null output's dump must hold the
   sent PCM bit for bit (widened to S32_LE as on the R26) at the frame the
   start time names.
4. Synthetic checks from the spec and the scripts' logic (not from a capture):
   setup/stream/audio/clock/start/stop/end_stream/teardown on the null output,
   sync against a fake master clock, disable/cancel, SOOD on unicast loopback,
   and an API audit of every native name the scripts reference.

Captures are read from where they are (outside the repo). Nothing is sent
off 127.0.0.1 and no multicast group is joined. Exits 77 when the captures
are missing.
"""
import json
import os
import re
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', '..', 'tools'))
import ll_decode  # noqa: E402
sys.path.insert(0, HERE)
import capture  # noqa: E402

CAPDIR = os.environ.get('RAAT_CAPTURE_DIR', '/home/yuifunami/r26-mainline/raat')
CAP1 = os.path.join(CAPDIR, 'capture', 'raat.pcap')
CAP2 = os.path.join(CAPDIR, 'capture2', 'raat.pcap')
CAP3 = os.path.join(CAPDIR, 'capture3', 'raat.pcap')
CAP3_HW = os.path.join(CAPDIR, 'capture3', 'hw_params.txt')

LL_REQUEST, LL_RESPONSE, LL_KEEPALIVE, LL_BEGIN_KA = 0x80000001, 0x80000002, 0x80000003, 0x80000004
SERVICE_ID = 'd7634b85-8190-470f-aa51-6cb5538dc1b9'

failures = []
passes = 0


def check(cond, what, detail=''):
    global passes
    if cond:
        passes += 1
        print(f'  ok   {what}')
    else:
        failures.append(what)
        print(f'  FAIL {what} {detail}')


# ---------------------------------------------------------------- captures

def streams(path):
    """{(src, sport, dst, dport): [(type, body), ...]} for streams with data."""
    out = {}
    for key, st in ll_decode.tcp_streams(path).items():
        if st['data']:
            out[key] = list(ll_decode.ll_frames(st['data']))
    return out


def pick(st, dport=None, sport=None, need=None):
    for (s, sp, d, dp), frames in st.items():
        if (dport is None or dp == dport) and (sport is None or sp == sport):
            if need is None or any(need(t, b) for t, b in frames):
                return frames
    return None


def is_req(name):
    def f(t, b):
        return t == LL_REQUEST and json.loads(b[4:]).get('request') == name
    return f


def parse_resp(body):
    return struct.unpack('>I', body[:4])[0], body[4], json.loads(body[5:])


# ---------------------------------------------------------------- comparison

def norm(obj, path=''):
    """Replace per-instance values: ids, uuids and ports."""
    if isinstance(obj, dict):
        r = {}
        for k, v in obj.items():
            p = f'{path}.{k}'
            if k in ('unique_id', 'controller_id') and isinstance(v, str):
                r[k] = '<uuid>'
            elif k in ('tcp_port', 'clock_port', 'audio_port_tcp') and isinstance(v, int):
                r[k] = '<port>'
            else:
                r[k] = norm(v, p)
        return r
    if isinstance(obj, list):
        return [norm(v, f'{path}[{i}]') for i, v in enumerate(obj)]
    return obj


def diff(a, b, path='', allowed=()):
    """Differences between got (a) and expected (b), minus allowed paths."""
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            p = f'{path}.{k}'
            if p in allowed:
                continue
            if k not in a:
                out.append(f'{p}: missing (expected {json.dumps(b[k])[:80]})')
            elif k not in b:
                out.append(f'{p}: unexpected {json.dumps(a[k])[:80]}')
            else:
                out += diff(a[k], b[k], p, allowed)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f'{path}: length {len(a)} != {len(b)}')
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff(x, y, f'{path}[{i}]', allowed)
    elif a != b:
        out.append(f'{path}: {json.dumps(a)[:80]} != {json.dumps(b)[:80]}')
    return out


# Deviations we make on purpose (PCM only, see RAAT-PROTOCOL.md 11.3).
ALLOWED_MANAGER = {
    '.devices[0].config.output.dsd_mode',
    '.device.config.output.dsd_mode',
}


def fmt_set(s):
    out = set()
    for e in s.split(','):
        rate, bits, chs = e.split('/')
        for ch in chs.split('|'):
            out.add((int(rate), int(bits), int(ch)))
    return out


# ---------------------------------------------------------------- sockets

class LL:
    def __init__(self, port):
        self.s = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.buf = b''

    def send_raw(self, typ, body):
        self.s.sendall(struct.pack('>II', 8 + len(body), typ) + body)

    def request(self, rid, obj):
        self.send_raw(LL_REQUEST, struct.pack('>I', rid) + json.dumps(obj).encode())

    def session(self, typ, body):
        self.send_raw(typ, body)

    def read(self, timeout=5.0, keepalives=False):
        deadline = time.monotonic() + timeout
        while True:
            if len(self.buf) >= 8:
                total, typ = struct.unpack('>II', self.buf[:8])
                if len(self.buf) >= total:
                    body = self.buf[8:total]
                    self.buf = self.buf[total:]
                    if typ == LL_KEEPALIVE and not keepalives:
                        continue
                    return typ, body
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            r, _, _ = select.select([self.s], [], [], left)
            if not r:
                return None
            d = self.s.recv(65536)
            if not d:
                return 'EOF'
            self.buf += d

    def close(self):
        self.s.close()


def sess_req(conn, rid, obj):
    conn.session(1, struct.pack('>i', rid) + json.dumps(obj).encode())


def read_sess(conn, timeout=5.0):
    f = conn.read(timeout)
    if f is None or f == 'EOF':
        return f
    typ, body = f
    if typ != 2:
        return ('other', typ, body)
    rid, final = struct.unpack('>iB', body[:5])
    return rid, final, json.loads(body[5:])


def until_rid(conn, rid, timeout=5.0):
    """Session replies up to and including the first one for rid."""
    got = []
    while True:
        f = read_sess(conn, timeout)
        if f is None or f == 'EOF' or f[0] == 'other':
            got.append(f)
            return got
        got.append(f)
        if f[0] == rid:
            return got


# ---------------------------------------------------------------- main

def main():
    args = sys.argv[1:]
    qemu = None
    if args and args[0] == '--qemu':
        qemu = args[1]
        args = args[2:]
    binary = os.path.abspath(args[0])
    if not (os.path.exists(CAP1) and os.path.exists(CAP2)):
        print(f'captures not found under {CAPDIR}; skipping')
        return 77

    st1, st2 = streams(CAP1), streams(CAP2)
    mgr_in = pick(st1, dport=9200, need=is_req('enumerate_devices'))
    mgr_out = pick(st2, sport=9200, need=lambda t, b: t == LL_RESPONSE)
    dev_in = pick(st2, need=is_req('load_script'))
    dev_port = [k for k, v in st2.items() if v is dev_in][0][3]
    dev_out = pick(st2, sport=dev_port)
    assert mgr_in and mgr_out and dev_in and dev_out, 'capture streams not found'

    exp_mgr = [parse_resp(b) for t, b in mgr_out if t == LL_RESPONSE]
    exp_dev = [(t, b) for t, b in dev_out if t != LL_KEEPALIVE]
    scripts = [json.loads(b[4:]) for t, b in dev_in if t == LL_REQUEST]
    exp_info = None
    for t, b in exp_dev:
        if t == 2 and struct.unpack('>i', b[:4])[0] == 2:
            exp_info = json.loads(b[5:])
    dev0 = exp_mgr[0][2]['devices'][0]

    with tempfile.TemporaryDirectory(prefix='raat-replay-') as tmp:
        # Fixture built from the capture at runtime: same card identity, uname
        # and PCM formats as the captured R26 (DSD entries are dropped by the
        # endpoint's fixture loader, as PCM only is offered).
        ad = exp_info['output']['info']['alsa_device']
        fixture = {
            'uname': exp_info['platform']['uname'],
            'devices': [{
                'device_id': dev0['device_id'], 'name': dev0['name'], 'vendor': dev0.get('vendor', ''),
                'usb_id': dev0.get('usb_id', ''), 'card_id': ad['id'], 'longname': ad['longname'],
                'components': ad['components'], 'driver': ad['driver'], 'mixername': ad['mixername'],
                'supported_formats': exp_info['output']['supported_formats'],
                'container': hw_container(),
            }],
        }
        sink = os.path.join(tmp, 'sink')
        os.mkdir(sink)
        fpath = os.path.join(tmp, 'fixture.json')
        json.dump(fixture, open(fpath, 'w'))
        cmd = ([qemu] if qemu else []) + [binary, '--data-dir', os.path.join(tmp, 'data'),
                                          '--bind', '127.0.0.1', '--manager-port', '0',
                                          '--sood-port', '0', '--no-multicast', '--fixture', fpath,
                                          '--name', 'replay-test', '--null-sink', sink, '-v']
        logf = open(os.path.join(tmp, 'endpoint.log'), 'w+')
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=logf, text=True)
        try:
            line = proc.stdout.readline()
            m = re.match(r'READY manager_port=(\d+) sood_port=(\d+)', line)
            if not m:
                print('endpoint did not start:', line)
                logf.seek(0)
                print(logf.read()[-3000:])
                return 1
            mport, sport = int(m.group(1)), int(m.group(2))
            rc = run(proc, mport, sport, mgr_in, exp_mgr, dev_in, exp_dev, exp_info, scripts, binary, qemu,
                     sink)
        finally:
            status = open(f'/proc/{proc.pid}/status').read() if proc.poll() is None else ''
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
            logf.seek(0)
            log = logf.read()
            if os.environ.get('RAAT_SHOW_LOG') or failures:
                print('---- endpoint log (tail) ----')
                print(log[-6000:])
        hwm = re.search(r'VmHWM:\s+(\d+) kB', status)
        rss = re.search(r'VmRSS:\s+(\d+) kB', status)
        if hwm:
            print(f'memory: VmHWM {int(hwm.group(1)) / 1024:.1f} MiB, VmRSS {int(rss.group(1)) / 1024:.1f} MiB'
                  + (' (includes qemu-arm itself)' if qemu else ''))
        check(proc.returncode == 0 or proc.returncode == -15, 'endpoint exits cleanly on SIGTERM',
              f'rc={proc.returncode}')
        check('ERROR' not in log and '[error]' not in log and 'Segmentation' not in log,
              'no errors in endpoint log')
    print(f'\n{passes} passed, {len(failures)} failed')
    for f in failures:
        print('  failed:', f)
    return 1 if failures else rc


def hw_container():
    """ALSA container the R26 used during playback (capture3/hw_params.txt)."""
    try:
        m = re.search(r'^format: (\S+)', open(CAP3_HW).read(), re.M)
        return m.group(1) if m else ''
    except OSError:
        return ''


def run(proc, mport, sport, mgr_in, exp_mgr, dev_in, exp_dev, exp_info, scripts, binary, qemu, sink):
    print('== manager replay (capture/ requests -> capture2 replies)')
    mc = LL(mport)
    sent = 0
    for t, b in mgr_in:
        if t in (LL_BEGIN_KA, LL_REQUEST):
            mc.send_raw(t, b)
            sent += 1
    got = []
    for _ in exp_mgr:
        f = mc.read()
        got.append(parse_resp(f[1]) if f and f != 'EOF' and f[0] == LL_RESPONSE else f)
    check(len(got) == len(exp_mgr), f'{len(exp_mgr)} manager replies for {sent} frames sent')
    dev_tcp_port = None
    for i, (g, e) in enumerate(zip(got, exp_mgr)):
        if not isinstance(g, tuple) or len(g) != 3:
            check(False, f'manager reply {i + 1}', repr(g))
            continue
        check(g[0] == e[0] and g[1] == e[1], f'manager reply {i + 1}: rid {g[0]} final {g[1]}',
              f'expected rid {e[0]} final {e[1]}')
        d = diff(norm(g[2]), norm(e[2]), allowed=ALLOWED_MANAGER)
        check(not d, f'manager reply {i + 1}: {e[2]["status"]} body matches (modulo ids, ports, dsd_mode)',
              '; '.join(d))
        if 'device' in g[2] and 'discovery_data' in g[2]['device']:
            dev_tcp_port = g[2]['device']['discovery_data']['tcp_port']
            check('code_signing_keys' not in g[2]['device']['discovery_data'], 'no code_signing_keys advertised')
    if not dev_tcp_port:
        check(False, 'device tcp_port in DeviceChanged')
        return 1

    print('== device replay (capture2 Core->endpoint -> capture2 replies)')
    dc = LL(dev_tcp_port)
    for t, b in dev_in:
        if t != LL_KEEPALIVE:
            dc.send_raw(t, b)
    # Barrier: an echo after the replayed requests. Everything before its
    # reply is what the replayed frames produced; rid 4 (subscribe_transport)
    # must produce nothing.
    sess_req(dc, 99, {'request': 'echo', 'barrier': True})
    got = []
    while True:
        f = dc.read(10)
        if f is None or f == 'EOF':
            got.append(f)
            break
        if f[0] == 2 and struct.unpack('>i', f[1][:4])[0] == 99:
            echo = json.loads(f[1][5:])
            break
        got.append(f)
    check(len(got) == len(exp_dev), f'{len(exp_dev)} device replies before the barrier', f'got {len(got)}')
    for i, (g, e) in enumerate(zip(got, exp_dev)):
        if not isinstance(g, tuple):
            check(False, f'device reply {i + 1}', repr(g))
            continue
        check(g[0] == e[0], f'device reply {i + 1}: frame type 0x{e[0]:x}', f'got 0x{g[0]:x}')
        if e[0] == LL_RESPONSE:
            gr, er = parse_resp(g[1]), parse_resp(e[1])
            check(gr == er, f'device reply {i + 1}: load_script rid {er[0]} final {er[1]} {er[2]}', repr(gr))
        elif e[0] == 2:
            grid, gfin = struct.unpack('>iB', g[1][:5])
            erid, efin = struct.unpack('>iB', e[1][:5])
            gj, ej = json.loads(g[1][5:]), json.loads(e[1][5:])
            check((grid, gfin) == (erid, efin), f'session reply {i + 1}: rid {erid} final {efin}',
                  f'got rid {grid} final {gfin}')
            allowed = set()
            if erid == 2:
                gf = fmt_set(gj['output']['supported_formats'])
                ef = {f for f in fmt_set(ej['output']['supported_formats']) if f[1] != 1}
                check(gf == ef, 'info: supported_formats = captured PCM set (DSD entries dropped)',
                      f'extra {sorted(gf - ef)[:5]} missing {sorted(ef - gf)[:5]}')
                check(all(f[1] != 1 for f in gf), 'info: no DSD (bits=1) formats offered')
                allowed = {'.output.supported_formats', '.output.info.config.dsd_mode'}
            d = diff(norm(gj), norm(ej), allowed=allowed)
            check(not d, f'session reply {i + 1}: rid {erid} body matches', '; '.join(d))
    check(not any(isinstance(g, tuple) and g[0] == 2 and struct.unpack('>i', g[1][:4])[0] == 4 for g in got),
          'subscribe_transport (rid 4) gets no reply, as captured')
    check(echo.get('status') == 'Success' and echo.get('barrier') is True, 'echo barrier answered')

    print('== keepalive')
    f = mc.read(3.0, keepalives=True)
    check(f is not None and f != 'EOF' and f[0] == LL_KEEPALIVE, 'manager sends 0x80000003 after LL_BEGIN_KEEPALIVE')

    if os.path.exists(CAP3):
        replay3(dc, sink)
    else:
        print(f'== playback replay skipped: {CAP3} not found')
    synthetic(dc, mc, exp_info)
    sood_test(sport, mport)
    api_audit(binary, qemu, scripts)
    return 0


# ---------------------------------------------------------------- capture3

class Clock:
    """Core-side clock reader: bursts of RAATCLKQ as in capture3."""

    def __init__(self, port):
        self.port = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(('127.0.0.1', 0))
        self.s.settimeout(1)
        self.rid = 1000
        self.samples = []  # (wall ns, local ns, delay ns)

    def burst(self, n=3):
        got = None
        for _ in range(n):
            self.rid += 1
            w = time.monotonic_ns()
            self.s.sendto(b'RAATCLKQ' + struct.pack('>i', self.rid), ('127.0.0.1', self.port))
            try:
                p, _ = self.s.recvfrom(64)
            except socket.timeout:
                continue
            if len(p) == 28 and p[:8] == b'RAATCLKR' and struct.unpack('>i', p[8:12])[0] == self.rid:
                t, d = struct.unpack('>qq', p[12:28])
                got = (w, t, d)
                self.samples.append(got)
            time.sleep(0.005)
        return got


def read_frame3(dc, timeout=5.0):
    f = dc.read(timeout)
    if f is None or f == 'EOF' or f[0] != 2:
        return f
    body = f[1]
    rid, fin = struct.unpack('>iB', body[:5])
    return rid, fin, json.loads(body[5:]), 8 + len(body)


def widen16(pcm):
    """16-bit LE samples into S32_LE, left-justified: what the R26 played."""
    out = bytearray(len(pcm) * 2)
    out[2::4] = pcm[0::2]
    out[3::4] = pcm[1::2]
    return bytes(out)


def replay3(dc, sink):
    print('== playback replay (capture3 Core->endpoint, shortened waits -> capture3 replies)')
    st = capture.tcp_streams(CAP3)
    sess_in = None
    for k, s in st.items():
        frames, _ = capture.ll_frames(s)
        reqs = [(s.time_at(o), json.loads(b[4:]), b) for o, t, b in frames if t == 1]
        if any(r[1].get('request') == 'setup' for r in reqs):
            sess_in = (k, reqs)
    if not sess_in:
        check(False, 'capture3: session connection found')
        return
    k_in, reqs = sess_in
    out = st[(k_in[2], k_in[3], k_in[0], k_in[1])]
    frames, lost = capture.ll_frames(out)
    lost_at = dict(lost)
    exp = []
    for i, (o, t, b) in enumerate(frames):
        if i in lost_at:
            exp.append(('LOST', lost_at[i]))
        if t == 2:
            rid, fin = struct.unpack('>iB', b[:5])
            exp.append((rid, fin, json.loads(b[5:])))
    cap_audio_port = next(e[2]['audio_port_tcp'] for e in exp if e[0] != 'LOST' and 'audio_port_tcp' in e[2])
    audio = sorted((s for k, s in st.items() if k[3] == cap_audio_port), key=lambda s: s.t0)
    print(f'  capture3: {len(reqs)} session requests, {len(audio)} audio connections, '
          f'{len([e for e in exp if e[0] != "LOST"])} replies, {sum(n for _, n in lost)} reply bytes lost by the capture')

    got = []
    clk = None
    audio_i = 0
    asock = None
    starts = []          # (setup index, start rid, local time, stream index)
    setup_n = 0
    stream_pcm = []      # PCM bytes sent per stream (from sample 0)
    cur_stream = None
    last_before_teardown = None
    first_after_setup = []

    def collect(until, timeout=5.0):
        while True:
            f = read_frame3(dc, timeout)
            if not isinstance(f, tuple) or len(f) != 4:
                got.append(('NONE', f))
                return None
            got.append(f)
            if until(f):
                return f

    for i, (t, req, raw) in enumerate(reqs):
        name, rid = req['request'], struct.unpack('>i', raw[:4])[0]
        if name == 'setup':
            if setup_n:
                time.sleep(0.5)  # capture3: 1 s between teardown and the next setup
            setup_n += 1
            dc.session(1, raw)
            f = collect(lambda f: f[0] == rid and (f[1] == 1 or f[2].get('status') == 'Success'))
            if not f or f[2].get('status') != 'Success':
                check(False, 'capture3: setup succeeded', repr(f))
                return
            clk = clk or Clock(f[2]['clock_port'])
            clk.port = f[2]['clock_port']
            audio_port = f[2]['audio_port_tcp']
            first_after_setup.append(clk.burst())
        elif name == 'stream':
            dc.session(1, raw)
            collect(lambda f: f[0] == rid)
            cmds = capture.audio_commands(audio[audio_i])
            audio_i += 1
            stream_pcm.append(b''.join(c[3] for c in cmds if c[1] == 0))
            cur_stream = len(stream_pcm) - 1
            asock = socket.create_connection(('127.0.0.1', audio_port), timeout=5)
            asock.sendall(capture.audio_serialize(cmds))
            collect(lambda f: f[0] == rid and f[2].get('status') in ('Ready', 'Ended'))
        elif name == 'start':
            c = clk.burst()
            body = dict(req)
            body['min_offset'] = c[2] + 20000000  # the Core: last delay + 20 ms
            check(req['min_offset'] - 20000000 > 40000000, f'capture3: start min_offset {req["min_offset"]} '
                  '= captured delay + 20 ms (R26 delay ~49 ms)')
            w = time.monotonic_ns()
            dc.session(1, raw[:4] + json.dumps(body).encode())
            f = collect(lambda f: f[0] == rid and f[1] == 1)
            if f and isinstance(f[2].get('time'), int):
                predicted = c[1] + (w - c[0]) + body['min_offset']
                check(abs(f[2]['time'] - predicted) < 30e6,
                      f'start rid {rid}: time = local clock + min_offset ({(f[2]["time"] - predicted) / 1e6:+.1f} ms)')
                starts.append((setup_n, rid, f[2]['time'], cur_stream))
            time.sleep(0.8)  # play a little; the capture played for seconds
            clk.burst()
        elif name in ('stop', 'end_stream'):
            dc.session(1, raw)
            collect(lambda f: f[0] == rid and f[1] == 1)
            if name == 'end_stream' and asock:
                asock.close()
                asock = None
            if name == 'stop':
                time.sleep(0.2)  # capture3: 5 s paused before end_stream
        elif name == 'teardown':
            c = clk.burst()
            last_before_teardown = last_before_teardown or c
            setup_rid = max(r2['request'] == 'setup' and struct.unpack('>i', rw[:4])[0] or 0
                            for _, r2, rw in reqs[:i])
            dc.session(1, raw)
            collect(lambda f: f[0] == setup_rid and f[1] == 1)
        else:
            check(False, f'capture3: unexpected request {name}')

    # ---- replies: same sequence; lost capture bytes must equal ours there
    ok, gi, detail = True, 0, ''
    allowed = {'.message.signal_path[0].method', '.message.signal_path[0].alsa_device.longname'}
    for j, e in enumerate(exp):
        if e[0] == 'LOST':
            nxt = next((x for x in exp[j + 1:] if x[0] != 'LOST'), None)
            size = 0
            while gi < len(got) and got[gi][0] != 'NONE' and not (
                    nxt and got[gi][0] == nxt[0] and got[gi][1] == nxt[1] and
                    got[gi][2].get('status') == nxt[2].get('status')):
                size += got[gi][3]
                gi += 1
            if size == 0 or (e[1] - size) % 8 or e[1] < size:  # remainder may be keepalives
                ok, detail = False, f'lost {e[1]} bytes in the capture, ours there {size}'
            continue
        if gi >= len(got) or got[gi][0] == 'NONE':
            ok, detail = False, f'reply {j} missing: {e}'
            break
        g = got[gi]
        gi += 1
        d = diff(norm(g[2]), norm(e[2]), allowed=allowed)
        d = [x for x in d if not x.startswith('.time:')]
        if (g[0], g[1]) != (e[0], e[1]) or d:
            ok, detail = False, f'reply {j}: got {g[:3]} expected {e} {d}'
            break
    extra = [g for g in got[gi:] if g[0] != 'NONE']
    check(ok and not extra, f'capture3: {len(exp)} replies match in order (rid, final, body modulo ports/time; '
          'lost capture bytes = our frames there)', detail or repr(extra[:3]))
    check(not any(g[0] != 'NONE' and g[2].get('status') == 'Dropout' for g in got),
          'capture3: no Dropout (none in the capture either)')

    # ---- clock behaviour seen in capture3
    s = clk.samples
    check(first_after_setup[0] and first_after_setup[0][1] < 500e6,
          f'clock starts near 0 at the first setup ({first_after_setup[0][1] / 1e6:.1f} ms)')
    if last_before_teardown and len(first_after_setup) > 1 and first_after_setup[1]:
        a, b = last_before_teardown, first_after_setup[1]
        dl, dw = b[1] - a[1], b[0] - a[0]
        check(0 <= dl < dw - 300e6, f'clock pauses between teardown and the next setup '
              f'(local +{dl / 1e6:.0f} ms over {dw / 1e6:.0f} ms wall)')
    delays = [x[2] for x in s]
    check(all(35e6 <= x <= 70e6 for x in delays),
          f'RAATCLKR delay {min(delays) / 1e6:.1f}-{max(delays) / 1e6:.1f} ms (R26: 49.1-49.2 ms on a 40 ms buffer)')
    seg = [x for x in s if x[0] <= (last_before_teardown or s[-1])[0]]
    rate = (seg[-1][1] - seg[0][1]) / (seg[-1][0] - seg[0][0])
    check(abs(rate - 1) < 0.01, f'local clock runs at wall rate within 1% ({rate:.4f})')

    # ---- bit-perfect output at the scheduled frame
    rate_hz, bpf = 44100, 8
    sinks = {}
    for n in sorted({x[0] for x in starts}):
        try:
            sinks[n] = open(os.path.join(sink, f'sink-{n}.raw'), 'rb').read()
        except OSError:
            sinks[n] = b''
    pos = {}
    for setup_i, rid, t_start, si in starts:
        exp_bytes = widen16(stream_pcm[si])
        nz = next(i for i in range(0, len(exp_bytes), bpf) if exp_bytes[i:i + bpf] != bytes(bpf))
        win = exp_bytes[nz:nz + 8192]
        data = sinks[setup_i]
        p = data.find(win)
        while p >= 0 and p % bpf:
            p = data.find(win, p + 1)
        if p < 0:
            check(False, f'start rid {rid}: stream {si + 1} PCM found in the output dump')
            continue
        f0 = (p - nz) // bpf
        pos[rid] = (setup_i, f0, t_start)
        # longest bit-exact run from the stream's first sample
        a = memoryview(data)[f0 * bpf:]
        bview = memoryview(exp_bytes)
        n = min(len(a), len(bview))
        lo, hi = 0, n // bpf
        while lo < hi:  # binary search on prefix equality
            mid = (lo + hi + 1) // 2
            if a[:mid * bpf] == bview[:mid * bpf]:
                lo = mid
            else:
                hi = mid - 1
        check(lo >= rate_hz // 2, f'start rid {rid}: {lo} frames ({lo / rate_hz:.2f} s) bit-exact, 16-bit widened '
              f'to S32_LE')
        before = data[:f0 * bpf]
        prev_end = max((q[1] + q[3] for q in pos.values() if q[0] == setup_i and q[1] < f0 and len(q) > 3),
                       default=0)
        check(not any(before[prev_end * bpf:]), f'start rid {rid}: only silence before the stream begins')
        pos[rid] = (setup_i, f0, t_start, lo)
    if 8 in pos and pos[8][0] == 1:
        k = pos[8][1]
        want = -(-pos[8][2] * rate_hz // 1000000000)
        check(abs(k - want) <= 1, f'first stream starts at device frame {k} = ceil(time * rate) = {want}')
    same = [(r, q) for r, q in sorted(pos.items())]
    for (r1, q1), (r2, q2) in zip(same, same[1:]):
        if q1[0] == q2[0]:
            want = round((q2[2] - q1[2]) * rate_hz / 1e9)
            check(abs((q2[1] - q1[1]) - want) <= 1,
                  f'start rid {r2}: frame offset from rid {r1} matches the time difference ({q2[1] - q1[1]} vs {want})')


def synthetic(dc, mc, exp_info):
    print('== synthetic playback on the null output (script logic, not a capture)')
    fmt = {'sample_type': 'pcm', 'sample_rate': 44100, 'bits_per_sample': 16, 'channels': 2}
    sess_req(dc, 10, {'request': 'setup', 'format': fmt})
    r = read_sess(dc)
    check(r and r[0] == 10 and r[2].get('status') == 'OutputMessage' and
          r[2]['message']['signal_path'][0]['quality'] == 'lossless',
          'setup context: OutputMessage with a lossless signal_path first', repr(r))
    r = [read_sess(dc)]
    ok = r[-1] and r[-1][0] == 10 and r[-1][1] == 0 and r[-1][2].get('status') == 'Success'
    check(ok, 'setup: then non-final Success with ports', repr(r[-1]))
    if not ok:
        return
    clock_port, audio_port = r[-1][2]['clock_port'], r[-1][2]['audio_port_tcp']

    cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cs.settimeout(2)
    cs.sendto(b'RAATCLKQ' + struct.pack('>i', 5), ('127.0.0.1', clock_port))
    try:
        pkt, _ = cs.recvfrom(64)
    except socket.timeout:
        pkt = b''
    ok = len(pkt) == 28 and pkt[:8] == b'RAATCLKR' and struct.unpack('>i', pkt[8:12])[0] == 5
    check(ok, 'RAATCLKQ -> RAATCLKR (28 bytes, rid echoed)', pkt[:12])
    t1 = struct.unpack('>qq', pkt[12:28]) if ok else (0, 0)
    check(t1[1] > 0, f'clock reply carries an output delay ({t1[1] / 1e6:.1f} ms)')

    sess_req(dc, 11, {'request': 'stream', 'first_seq': 0, 'stream_id': 7, 'buffer_size': 1,
                      'ready_threshold': 0.05})
    r = read_sess(dc)
    check(r and r[0] == 11 and r[1] == 0 and r[2]['status'] == 'Buffering', 'stream: non-final Buffering', repr(r))

    a = socket.create_connection(('127.0.0.1', audio_port), timeout=5)
    n = 4410
    pcm = bytes((i * 7) & 0xff for i in range(n * 4))
    a.sendall(bytes([2]) + struct.pack('>i', 7) + bytes([3]) + struct.pack('>q', 0) +
              bytes([4]) + struct.pack('>dd', 0.0, 0.0) + bytes([1]) + struct.pack('>i', 0) +
              bytes([0]) + struct.pack('>ii', n, len(pcm)) + pcm)
    r = read_sess(dc)
    check(r and r[0] == 11 and r[2]['status'] == 'Ready', 'stream context: Ready after enough audio', repr(r))

    sess_req(dc, 12, {'request': 'start', 'stream_sample': 0, 'min_offset': 150000000})
    r = until_rid(dc, 12)
    sts = [x[2]['status'] for x in r if isinstance(x, tuple) and len(x) == 3]
    check('Playing' in sts and r[-1][2].get('status') == 'Success' and isinstance(r[-1][2].get('time'), int),
          'start: stream Playing + final Success with time', repr(r))

    # The 0.1 s sent runs out; the stats timer reports the dropout.
    r = read_sess(dc, 3)
    check(r and r[0] == 11 and r[2]['status'] == 'Dropout' and r[2]['samples'] > 0,
          'stream context: Dropout once the audio runs out', repr(r))

    # sync against a fake master clock on loopback
    master = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    master.bind(('127.0.0.1', 0))
    sess_req(dc, 13, {'request': 'sync', 'host': '127.0.0.1', 'port': master.getsockname()[1],
                      'new_source': True})
    answered = 0
    deadline = time.monotonic() + 3
    reply = None
    while time.monotonic() < deadline and reply is None:
        rr, _, _ = select.select([master, dc.s], [], [], 0.5)
        if master in rr:
            q, src = master.recvfrom(64)
            if q[:8] == b'RAATCLKQ':
                master.sendto(b'RAATCLKR' + q[8:12] + struct.pack('>qq', time.monotonic_ns(), 0), src)
                answered += 1
        if dc.s in rr or dc.buf:
            f = read_sess(dc, 0.1)
            if isinstance(f, tuple) and f[0] == 13:
                reply = f
    check(reply and reply[2]['status'] == 'Success' and answered >= 5,
          f'sync: final Success after {answered} RAATCLKQ to the master', repr(reply))

    sess_req(dc, 14, {'request': 'stop'})
    r = until_rid(dc, 14)
    sts = [x[2]['status'] for x in r if isinstance(x, tuple) and len(x) == 3]
    check('Stopped' in sts and r[-1][2]['status'] == 'Success', 'stop: Stopped + Success', repr(r))

    sess_req(dc, 15, {'request': 'end_stream'})
    r = until_rid(dc, 15)
    sts = [(x[0], x[1], x[2]['status']) for x in r if isinstance(x, tuple) and len(x) == 3]
    check((11, 1, 'Ended') in sts and sts[-1] == (15, 1, 'Success'), 'end_stream: final Ended on stream + Success',
          repr(sts))

    sess_req(dc, 16, {'request': 'teardown'})
    sess_req(dc, 17, {'request': 'no_such_request'})
    r = until_rid(dc, 17)
    sts = [(x[0], x[1], x[2]['status']) for x in r if isinstance(x, tuple) and len(x) == 3]
    check((10, 1, 'Teardown') in sts and not any(s[0] == 16 for s in sts),
          'teardown: final Teardown on the setup context, none on its own', repr(sts))
    check(sts[-1] == (17, 1, 'NotSupported'), 'unknown session request: NotSupported', repr(sts))
    a.close()

    # setup with a format the device does not take -> error, no resampling
    sess_req(dc, 18, {'request': 'setup', 'format': dict(fmt, sample_rate=22050)})
    r = until_rid(dc, 18)
    check(r[-1][1] == 1 and r[-1][2]['status'] == 'UnexpectedError' and 'FORMAT_NOT_SUPPORTED' in r[-1][2]['message'],
          'setup at an unsupported rate fails (no resampling)', repr(r[-1]))
    sess_req(dc, 19, {'request': 'setup', 'format': {'sample_type': 'dsd', 'sample_rate': 2822400,
                                                     'bits_per_sample': 1, 'channels': 2}})
    r = until_rid(dc, 19)
    check(r[-1][1] == 1 and r[-1][2]['status'] != 'Success', 'setup with DSD is refused', repr(r[-1]))

    # force_exit closes this session, not the process
    sess_req(dc, 20, {'request': 'force_exit'})
    f = dc.read(3)
    check(f == 'EOF', 'force_exit: endpoint closes the session connection', repr(f))
    dc.close()

    print('== manager: disable / cancel / unknown')
    mc.request(3, {'request': 'disable_device', 'subscription_id': '22'})
    rs = []
    for _ in range(3):
        f = mc.read()
        if f and f != 'EOF':
            rs.append(parse_resp(f[1]))
    st = [(r[0], r[1], r[2]['status']) for r in rs]
    check((2, 1, 'Canceled') in st and (3, 1, 'Success') in st and (1, 0, 'DeviceChanged') in st,
          'disable_device: Canceled on the enable, DeviceChanged, Success', repr(st))
    dch = [r for r in rs if r[2]['status'] == 'DeviceChanged']
    check(dch and 'discovery_data' not in dch[0][2]['device'], 'disabled device has no discovery_data')
    mc.request(4, {'request': 'bogus'})
    r = parse_resp(mc.read()[1])
    check(r == (4, 1, {'status': 'NotSupported'}), 'unknown manager request: NotSupported', repr(r))
    mc.request(5, {'request': 'cancel_enumerate_devices', 'subscription_id': '0'})
    rs = [parse_resp(mc.read()[1]) for _ in range(2)]
    check([(r[0], r[1], r[2]['status']) for r in rs] == [(1, 1, 'Canceled'), (5, 1, 'Success')],
          'cancel_enumerate_devices: Canceled then Success', repr(rs))
    mc.close()


def sood_q(kv):
    p = b'SOOD\x02Q'
    for k, v in kv.items():
        kb = k.encode()
        p += bytes([len(kb)]) + kb
        if v is None:
            p += b'\xff\xff'
        else:
            vb = v.encode()
            p += struct.pack('>H', len(vb)) + vb
    return p


def sood_parse(p):
    assert p[:6] == b'SOOD\x02R', p[:6]
    off, out = 6, {}
    while off < len(p):
        kl = p[off]
        k = p[off + 1:off + 1 + kl].decode()
        off += 1 + kl
        vl = struct.unpack('>H', p[off:off + 2])[0]
        off += 2
        if vl == 0xFFFF:
            out[k] = None
        else:
            out[k] = p[off:off + vl].decode()
            off += vl
    return out


def sood_test(sport, mport):
    print('== SOOD (unicast on loopback; no multicast)')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 0))
    s.settimeout(1)
    s.sendto(sood_q({'service_id': SERVICE_ID, '_tid': 'tid-1'}), ('127.0.0.1', sport))
    try:
        r = sood_parse(s.recvfrom(2048)[0])
    except socket.timeout:
        r = {}
    check(r.get('_tid') == 'tid-1' and r.get('service_id') == SERVICE_ID, 'SOOD R echoes _tid and service_id', repr(r))
    check(r.get('tcp_port') == str(mport), 'SOOD R carries the manager tcp_port')
    for k in ('unique_id', 'machine_id', 'machine_name', 'os_version', 'raat_version', 'protocol_version',
              'config_version', 'is_dev'):
        check(k in r, f'SOOD R has {k}')
    check('code_signing_keys' not in r, 'SOOD R has no code_signing_keys')
    s.sendto(sood_q({'service_id': SERVICE_ID, '_tid': 'tid-1'}), ('127.0.0.1', sport))
    s.sendto(sood_q({'service_id': '00000000-0000-0000-0000-000000000000', '_tid': 'tid-2'}), ('127.0.0.1', sport))
    try:
        extra = s.recvfrom(2048)[0]
    except socket.timeout:
        extra = None
    check(extra is None, 'SOOD ignores a duplicate _tid and a foreign service_id', repr(extra))
    # _replyport redirects the answer (still loopback)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2.bind(('127.0.0.1', 0))
    s2.settimeout(1)
    s.sendto(sood_q({'service_id': SERVICE_ID, '_tid': 'tid-3', '_replyport': str(s2.getsockname()[1])}),
             ('127.0.0.1', sport))
    try:
        r = sood_parse(s2.recvfrom(2048)[0])
    except socket.timeout:
        r = {}
    check(r.get('_tid') == 'tid-3', 'SOOD honours _replyport')


def api_audit(binary, qemu, scripts):
    print('== API audit: native names the scripts use vs. what the endpoint registers')
    out = subprocess.run(([qemu] if qemu else []) + [binary, '--dump-lua-api'], capture_output=True, text=True,
                         timeout=30).stdout
    have = {line.split(':')[0] if not line.startswith('method:') else ':'.join(line.split(':')[:2])
            for line in out.split()}
    methods = {n.split('.', 1)[1] for n in have if n.startswith('method:')}
    src = '\n'.join(s['script'] for s in scripts)
    src = re.sub(r'--[^\n]*', '', src)  # comments
    refs = set(re.findall(r'\b((?:raat|uv|buffer|stream|codec)(?:\.[a-zA-Z_]\w*)+)', src))
    # Fields the scripts only probe or touch behind an is_supported check that
    # is false here; their absence is the correct answer.
    optional = re.compile(r'^raat\.(port_range|recv_buffer_size_hint|codecs)|'
                          r'^raat\.(volume|transport|source_selection|app_channel)\.(?!is_supported$)|'
                          r'^uv\.(udp_recv_start_noalloc|read_start_noalloc)$|'
                          r'^raat\.(volume|transport|source_selection)\.info$')
    missing = sorted(r for r in refs if r not in have and not optional.search(r))
    check(not missing, f'{len(refs)} raat./uv./buffer./stream./codec. references resolve', repr(missing))
    called = set(re.findall(r':([a-zA-Z_]\w*)\s*\(', src))
    defined = set(re.findall(r'function\s+[\w.]+[.:]([a-zA-Z_]\w*)', src))
    defined |= set(re.findall(r'\.([a-zA-Z_]\w*)\s*=\s*function', src))
    # read_start_noalloc is probed (uv.read_start_noalloc is nil here);
    # decode_to_stream needs a codec object, which only exists with wire_codec,
    # and raat.codecs is nil so the Core sends none (RAAT-PROTOCOL.md 11.6).
    probed = {'read_start_noalloc', 'decode_to_stream'}
    unknown = sorted(c for c in called if c not in methods and c not in defined and c not in probed)
    check(not unknown, f'{len(called)} method calls resolve to native or script-defined methods', repr(unknown))


if __name__ == '__main__':
    sys.exit(main())
