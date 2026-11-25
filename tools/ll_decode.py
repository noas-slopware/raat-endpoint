#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reassemble TCP streams from a classic pcap and decode RAAT "LL" frames.

usage: ll_decode.py <in.pcap> <outdir>

Writes <outdir>/frames.jsonl (one decoded frame per line), <outdir>/udp.jsonl
(UDP, e.g. the clock exchange) and, for every
load_script request, <outdir>/script-<n>.lua with the script text.
Handles in-order data only (enough for a LAN capture); retransmits are dropped.
"""
import json
import os
import struct
import sys


def packets(path):
    d = open(path, 'rb').read()
    off = 24
    while off + 16 <= len(d):
        sec, usec, incl, _ = struct.unpack('<IIII', d[off:off + 16])
        if off + 16 + incl > len(d):
            break  # truncated last record (capture cut off mid-write)
        pkt = d[off + 16:off + 16 + incl]
        off += 16 + incl
        if len(pkt) >= 34:  # ethernet + minimal IPv4 header
            yield sec + usec / 1e6, pkt


def tcp_streams(path):
    streams = {}
    for ts, pkt in packets(path):
        ip = pkt[14:]
        if ip[9] != 6:  # TCP only here; UDP (clock sync) is listed by udp_packets()
            continue
        ihl = (ip[0] & 0xf) * 4
        tot = struct.unpack('>H', ip[2:4])[0]
        src, dst = ip[12:16], ip[16:20]
        tcp = ip[ihl:tot]
        sp, dp, seq = struct.unpack('>HHI', tcp[:8])
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        payload = tcp[doff:]
        key = ('.'.join(map(str, src)), sp, '.'.join(map(str, dst)), dp)
        st = streams.setdefault(key, {'next': None, 'data': bytearray(), 't0': ts})
        if flags & 0x02:  # SYN
            st['next'] = (seq + 1) & 0xffffffff
            continue
        if not payload:
            continue
        if st['next'] is None:
            st['next'] = seq
        if seq == st['next']:
            st['data'] += payload
            st['next'] = (seq + len(payload)) & 0xffffffff
    return streams


def udp_packets(path):
    for ts, pkt in packets(path):
        ip = pkt[14:]
        if ip[9] != 17:
            continue
        ihl = (ip[0] & 0xf) * 4
        sp, dp, ulen = struct.unpack('>HHH', ip[ihl:ihl + 6])
        yield ts, '.'.join(map(str, ip[12:16])), sp, '.'.join(map(str, ip[16:20])), dp, bytes(ip[ihl + 8:ihl + ulen])


def ll_frames(data):
    off = 0
    while off + 8 <= len(data):
        total, typ = struct.unpack('>II', data[off:off + 8])
        if total < 8 or off + total > len(data):
            break
        yield typ, bytes(data[off + 8:off + total])
        off += total


def main():
    pcap, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    out = open(os.path.join(outdir, 'frames.jsonl'), 'w')
    nscript = 0
    for key, st in tcp_streams(pcap).items():
        src, sp, dst, dp = key
        for typ, body in ll_frames(st['data']):
            rec = {'from': f'{src}:{sp}', 'to': f'{dst}:{dp}', 'type': f'0x{typ:08x}', 'len': len(body)}
            js = None
            if typ == 0x80000001 and len(body) >= 4:
                rec['req_id'] = struct.unpack('>I', body[:4])[0]
                js = body[4:]
            elif typ == 0x80000002 and len(body) >= 5:
                rec['req_id'] = struct.unpack('>I', body[:4])[0]
                rec['final'] = body[4]
                js = body[5:]
            elif typ == 0x80000004 and len(body) == 8:
                rec['interval_ms'], rec['timeout_ms'] = struct.unpack('>II', body)
            elif typ < 0x80000000:
                rec['session_head'] = body[:64].hex()
            if js is not None:
                try:
                    obj = json.loads(js)
                    rec['json'] = obj
                    if isinstance(obj, dict) and obj.get('request') == 'load_script':
                        script = obj.get('script') or obj.get('code') or obj.get('source')
                        nscript += 1
                        if isinstance(script, str):
                            open(os.path.join(outdir, f'script-{nscript}.lua'), 'w').write(script)
                except ValueError:
                    rec['raw'] = js[:200].decode(errors='replace')
            out.write(json.dumps(rec) + '\n')
    with open(os.path.join(outdir, 'udp.jsonl'), 'w') as u:
        nudp = 0
        for ts, src, sp, dst, dp, body in udp_packets(pcap):
            nudp += 1
            u.write(json.dumps({'t': round(ts, 6), 'from': f'{src}:{sp}', 'to': f'{dst}:{dp}',
                                'len': len(body), 'head': body[:48].hex()}) + '\n')
    print(f'{nscript} load_script request(s), {nudp} UDP packet(s)')


if __name__ == '__main__':
    main()
