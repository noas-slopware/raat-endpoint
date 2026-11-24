"""Capture parsing for the replay test: TCP reassembly that tolerates loss.

The capture tool on the endpoint drops packets now and then. Streams are
rebuilt from every segment sorted by sequence number; missing ranges are
zero-filled and reported, so parsers can resync after them.
"""
import bisect
import re
import struct


def packets(path):
    d = open(path, 'rb').read()
    off = 24
    while off + 16 <= len(d):
        sec, usec, incl, _ = struct.unpack('<IIII', d[off:off + 16])
        if off + 16 + incl > len(d):
            break  # truncated last record
        pkt = d[off + 16:off + 16 + incl]
        off += 16 + incl
        if len(pkt) >= 34:
            yield sec + usec / 1e6, pkt


class Stream:
    def __init__(self, key):
        self.key = key            # (src, sport, dst, dport)
        self.data = b''
        self.gaps = []            # [(start, end)) byte ranges that were lost
        self.t0 = None
        self._times = []          # (offset, timestamp) of each segment

    def time_at(self, off):
        i = bisect.bisect_right([o for o, _ in self._times], off) - 1
        return self._times[max(i, 0)][1] if self._times else self.t0

    def in_gap(self, a, b):
        return any(a < ge and b > gs for gs, ge in self.gaps)


def tcp_streams(path):
    segs, syn, first = {}, {}, {}
    for ts, pkt in packets(path):
        ip = pkt[14:]
        if len(ip) < 20 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0xf) * 4
        tot = struct.unpack('>H', ip[2:4])[0]
        tcp = ip[ihl:tot]
        sp, dp, seq = struct.unpack('>HHI', tcp[:8])
        doff = (tcp[12] >> 4) * 4
        key = ('.'.join(map(str, ip[12:16])), sp, '.'.join(map(str, ip[16:20])), dp)
        first.setdefault(key, ts)
        if tcp[13] & 0x02:
            syn[key] = (seq + 1) & 0xffffffff
            continue
        if tcp[doff:]:
            segs.setdefault(key, []).append((ts, seq, bytes(tcp[doff:])))
    out = {}
    for key, ss in segs.items():
        base = syn.get(key, min(s for _, s, _ in ss))
        st = Stream(key)
        st.t0 = first[key]
        data = bytearray()
        end = 0
        for rel, ts, pl in sorted(((s - base) & 0xffffffff, ts, pl) for ts, s, pl in ss):
            if rel > end:
                st.gaps.append((end, rel))
                data += bytes(rel - end)
                end = rel
            if rel + len(pl) > end:
                st._times.append((end, ts))
                data += pl[end - rel:]
                end = rel + len(pl)
        st.data = bytes(data)
        out[key] = st
    return out


def udp_packets(path):
    for ts, pkt in packets(path):
        ip = pkt[14:]
        if len(ip) < 20 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0xf) * 4
        sp, dp, ulen = struct.unpack('>HHH', ip[ihl:ihl + 6])
        yield (ts, '.'.join(map(str, ip[12:16])), sp, '.'.join(map(str, ip[16:20])), dp,
               bytes(ip[ihl + 8:ihl + ulen]))


_SESSION_HDR = re.compile(rb'\x00\x00\x00\x02.{4}[\x00\x01]\{|\x00\x00\x00\x01.{4}\{', re.S)


def ll_frames(st):
    """[(offset, type, body)] plus [(after_index, lost_bytes)] for each resync.

    A frame overlapping a lost range is skipped; parsing resumes at the next
    plausible session frame header (type 1 or 2 with a JSON body)."""
    d, off, frames, lost = st.data, 0, [], []
    while off + 8 <= len(d):
        total, typ = struct.unpack('>II', d[off:off + 8])
        ok = 8 <= total <= 0x400008 and off + total <= len(d) and not st.in_gap(off, off + total)
        ok = ok and (typ >= 0x80000000 or typ in (1, 2, 3))
        if not ok:
            m = _SESSION_HDR.search(d, off + 1)
            nxt = None
            while m:
                cand = m.start() - 4
                if cand >= 0 and not st.in_gap(cand, cand + 12):
                    nxt = cand
                    break
                m = _SESSION_HDR.search(d, m.start() + 1)
            if nxt is None:
                break
            lost.append((len(frames), sum(min(ge, nxt) - max(gs, off) for gs, ge in st.gaps
                                          if gs < nxt and ge > off)))
            off = nxt
            continue
        frames.append((off, typ, d[off + 8:off + total]))
        off += total
    return frames, lost


AUDIO_HDR = {0: 8, 1: 4, 2: 4, 3: 8, 4: 16, 5: 8}


def audio_commands(st):
    """Parse the audio command stream (spec 13.5) of one connection.

    Returns [(offset, cmd, header_values, payload)]. A DATA command whose header
    was lost is rebuilt from the chunk size the stream uses everywhere else, and
    parsing resumes at the next intact DATA header; payload bytes that were lost
    stay zero-filled (they are what the test then sends)."""
    d, off, out = st.data, 0, []
    chunk = None
    while off < len(d):
        if st.in_gap(off, off + 17):
            if not chunk:
                break
            pat = b'\x00' + struct.pack('>ii', *chunk)
            ge = min(e for s, e in st.gaps if e > off)
            m = d.find(pat, ge)
            if m < 0:
                break
            step = 9 + chunk[1]
            if (m - off) % step == 0:
                # Regular layout: the lost headers sat exactly here. Keep those
                # chunks (with whatever payload bytes survived) so sample
                # positions stay as the Core sent them.
                while off < m:
                    out.append((off, 0, chunk, d[off + 9:off + step]))
                    off += step
            off = m
            continue
        c = d[off]
        hl = AUDIO_HDR.get(c)
        if hl is None:
            break
        h = d[off + 1:off + 1 + hl]
        if c in (0, 5):
            n, nb = struct.unpack('>ii', h)
            chunk = chunk or (n, nb)
            out.append((off, c, (n, nb), d[off + 1 + hl:off + 1 + hl + nb]))
            off += 1 + hl + nb
            continue
        v = {1: '>i', 2: '>i', 3: '>q', 4: '>dd'}[c]
        out.append((off, c, struct.unpack(v, h), b''))
        off += 1 + hl
    return out


def audio_serialize(cmds):
    b = bytearray()
    for _, c, v, pl in cmds:
        b.append(c)
        b += struct.pack({0: '>ii', 1: '>i', 2: '>i', 3: '>q', 4: '>dd', 5: '>ii'}[c], *v)
        b += pl
    return bytes(b)
