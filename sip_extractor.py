import re
import socket
import struct
import sys
from collections import OrderedDict
import dpkt

SIP_METHODS = (
    b"INVITE", b"ACK", b"BYE", b"CANCEL", b"REGISTER",
    b"OPTIONS", b"PRACK", b"REFER", b"NOTIFY", b"UPDATE", b"INFO", b"MESSAGE",
)
CALL_ID_RE = re.compile(rb"^(?:Call-ID|i)\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
FROM_RE = re.compile(rb"^(?:From|f)\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
TO_RE = re.compile(rb"^(?:To|t)\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
SDP_CONN_RE = re.compile(rb"^c=IN IP[46]\s+(\S+)", re.MULTILINE)
SDP_MEDIA_RE = re.compile(rb"^m=(?:audio|video)\s+(\d+)", re.MULTILINE)

DLT_LINUX_SLL2 = 276  # tcpdump -i any on modern Linux kernels


def inet_to_str(inet: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def unpack_ip(buf: bytes, datalink: int):
    """Unpacks IPv4/IPv6 from Ethernet, Linux SLL, Linux SLL2, or Raw IP."""
    try:
        if datalink == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            return eth.data if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
        elif datalink == dpkt.pcap.DLT_LINUX_SLL:
            sll = dpkt.sll.SLL(buf)
            return sll.data if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
        elif datalink == DLT_LINUX_SLL2:
            if len(buf) < 20:
                return None
            proto = struct.unpack("!H", buf[:2])[0]
            if proto == 0x0800:
                return dpkt.ip.IP(buf[20:])
            elif proto == 0x86DD:
                return dpkt.ip6.IP6(buf[20:])
        elif datalink in (dpkt.pcap.DLT_RAW, 12, 101):
            version = buf[0] >> 4
            return dpkt.ip.IP(buf) if version == 4 else dpkt.ip6.IP6(buf)
    except Exception:
        return None
    return None


def unwrap_gtpu(udp_payload: bytes):
    """Extracts inner IPv4/IPv6 packet if UDP payload is a GTP-U G-PDU (0xff)."""
    if len(udp_payload) < 12:
        return None
    flags, msg_type = udp_payload[0], udp_payload[1]
    if (flags >> 5) != 1 or msg_type != 0xFF:
        return None
    offset = 8
    if flags & 0x07:  # Sequence, N-PDU, or Next Extension Header present
        if len(udp_payload) < 12:
            return None
        next_ext = udp_payload[11]
        offset = 12
        while next_ext != 0 and offset < len(udp_payload):
            ext_len = udp_payload[offset] * 4
            if ext_len == 0 or offset + ext_len > len(udp_payload):
                return None
            next_ext = udp_payload[offset + ext_len - 1]
            offset += ext_len
    if offset >= len(udp_payload):
        return None
    inner = udp_payload[offset:]
    try:
        version = inner[0] >> 4
        if version == 4:
            return dpkt.ip.IP(inner)
        elif version == 6:
            return dpkt.ip6.IP6(inner)
    except Exception:
        return None
    return None


def is_sip(payload: bytes) -> bool:
    head = payload.lstrip()
    return head.startswith(b"SIP/2.0") or any(head.startswith(m + b" ") for m in SIP_METHODS)


def extract_sdp_endpoints(payload: bytes) -> set[tuple[str, int]]:
    endpoints = set()
    if b"\r\n\r\n" not in payload:
        return endpoints
    body = payload.split(b"\r\n\r\n", 1)[1]
    conn_match = SDP_CONN_RE.search(body)
    if conn_match:
        ip = conn_match.group(1).decode("ascii", errors="ignore").strip()
        for port_match in SDP_MEDIA_RE.finditer(body):
            endpoints.add((ip, int(port_match.group(1))))
    return endpoints


class IPv4Reassembler:
    """Bounded IPv4 fragment reassembler that retains original frames for PCAP export."""

    def __init__(self, max_flows: int = 4096):
        self.buffers: OrderedDict[tuple, dict] = OrderedDict()
        self.max_flows = max_flows

    def add(self, ip: dpkt.ip.IP, ts: float, raw_buf: bytes):
        mf = bool(ip.off & 0x2000)
        offset = (ip.off & 0x1FFF) * 8
        if not mf and offset == 0:
            return bytes(ip.data), [(ts, raw_buf)]

        key = (ip.src, ip.dst, ip.id, ip.p)
        if key not in self.buffers:
            if len(self.buffers) >= self.max_flows:
                self.buffers.popitem(last=False)
            self.buffers[key] = {"frags": [], "end_seen": False}

        entry = self.buffers[key]
        entry["frags"].append((offset, bytes(ip.data), ts, raw_buf))
        if not mf:
            entry["end_seen"] = True

        if not entry["end_seen"]:
            return None

        sorted_frags = sorted(entry["frags"], key=lambda x: x[0])
        if sorted_frags[0][0] != 0:
            return None

        cursor = 0
        chunks = []
        raw_packets = []
        for off, data, f_ts, f_buf in sorted_frags:
            if off > cursor:
                return None  # Missing middle fragment
            if off + len(data) > cursor:
                chunks.append(data[cursor - off:])
                cursor = off + len(data)
            raw_packets.append((f_ts, f_buf))

        del self.buffers[key]
        return b"".join(chunks), raw_packets


def iter_sip_datagrams(reader: dpkt.pcap.Reader, stats: dict):
    """Yields (src_ip, dst_ip, l4_proto, sport, dport, payload, raw_pkts) across IP/UDP/TCP/GTP-U."""
    datalink = reader.datalink()
    stats["datalink"] = datalink
    reassembler = IPv4Reassembler()
    tcp_streams: OrderedDict[tuple, bytearray] = OrderedDict()

    for ts, buf in reader:
        stats["total_packets"] += 1
        ip = unpack_ip(buf, datalink)
        if ip is None:
            continue
        stats["ip_packets"] += 1

        # Unwrap GTP-U tunnel if outer packet is UDP port 2152
        if isinstance(ip, dpkt.ip.IP) and ip.p == dpkt.ip.IP_PROTO_UDP and not (ip.off & 0x3FFF):
            udp = ip.data
            if isinstance(udp, dpkt.udp.UDP) and (udp.sport == 2152 or udp.dport == 2152):
                inner_ip = unwrap_gtpu(bytes(udp.data))
                if inner_ip is not None:
                    stats["gtpu_packets"] += 1
                    ip = inner_ip

        if isinstance(ip, dpkt.ip.IP):
            is_frag = bool(ip.off & 0x3FFF)
            if is_frag:
                stats["fragmented_packets"] += 1
            res = reassembler.add(ip, ts, buf)
            if res is None:
                continue
            l4_bytes, raw_pkts = res
            src_ip, dst_ip = inet_to_str(ip.src), inet_to_str(ip.dst)
            proto = ip.p

            if proto == dpkt.ip.IP_PROTO_UDP:
                if len(l4_bytes) < 8:
                    continue
                sport, dport = struct.unpack("!HH", l4_bytes[:4])
                yield src_ip, dst_ip, "UDP", sport, dport, l4_bytes[8:], raw_pkts

            elif proto == dpkt.ip.IP_PROTO_TCP:
                try:
                    tcp = dpkt.tcp.TCP(l4_bytes)
                except Exception:
                    continue
                payload = bytes(tcp.data)
                if not payload:
                    continue
                flow_key = (src_ip, tcp.sport, dst_ip, tcp.dport)
                if is_sip(payload) or flow_key in tcp_streams:
                    if flow_key not in tcp_streams:
                        if len(tcp_streams) >= 2048:
                            tcp_streams.popitem(last=False)
                        tcp_streams[flow_key] = bytearray()
                    tcp_streams[flow_key].extend(payload)
                    if len(tcp_streams[flow_key]) > 65536:
                        del tcp_streams[flow_key]
                        continue
                    yield src_ip, dst_ip, "TCP", tcp.sport, tcp.dport, bytes(tcp_streams[flow_key]), raw_pkts

        elif isinstance(ip, dpkt.ip6.IP6):
            src_ip, dst_ip = inet_to_str(ip.src), inet_to_str(ip.dst)
            if isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                yield src_ip, dst_ip, "UDP", udp.sport, udp.dport, bytes(udp.data), [(ts, buf)]
            elif isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                yield src_ip, dst_ip, "TCP", tcp.sport, tcp.dport, bytes(tcp.data), [(ts, buf)]


def list_calls(input_pcap: str):
    stats = {"datalink": 0, "total_packets": 0, "ip_packets": 0, "fragmented_packets": 0, "gtpu_packets": 0}
    calls: dict[str, dict] = {}

    with open(input_pcap, "rb") as f_in:
        reader = dpkt.pcap.Reader(f_in)
        for src_ip, dst_ip, proto, sport, dport, payload, raw_pkts in iter_sip_datagrams(reader, stats):
            if not payload or not is_sip(payload):
                continue
            cid_m = CALL_ID_RE.search(payload)
            if not cid_m:
                continue
            cid = cid_m.group(1).decode("utf-8", errors="replace").strip()
            first_line = payload.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            if cid not in calls:
                from_m = FROM_RE.search(payload)
                to_m = TO_RE.search(payload)
                calls[cid] = {
                    "count": 0,
                    "first_msg": first_line,
                    "from": from_m.group(1).decode("utf-8", errors="replace").strip() if from_m else "-",
                    "to": to_m.group(1).decode("utf-8", errors="replace").strip() if to_m else "-",
                }
            calls[cid]["count"] += len(raw_pkts)

    print(f"PCAP Stats: datalink={stats['datalink']}, total={stats['total_packets']}, "
          f"ip={stats['ip_packets']}, fragments={stats['fragmented_packets']}, gtpu={stats['gtpu_packets']}")
    print(f"Discovered {len(calls)} SIP Call-IDs:\n")
    for cid, info in list(calls.items())[:30]:
        print(f"  Call-ID : {cid}")
        print(f"    Packets: {info['count']} | Start: {info['first_msg']}")
        print(f"    From   : {info['from']}")
        print(f"    To     : {info['to']}\n")


def extract_call(input_pcap: str, output_pcap: str, target_call_id: str):
    target_bytes = target_call_id.encode("utf-8").strip()
    stats = {"datalink": 0, "total_packets": 0, "ip_packets": 0, "fragmented_packets": 0, "gtpu_packets": 0}
    rtp_endpoints: set[tuple[str, int]] = set()
    flow_events = []
    matched_packets = 0
    seen_cids = set()

    with open(input_pcap, "rb") as f_in, open(output_pcap, "wb") as f_out:
        reader = dpkt.pcap.Reader(f_in)
        writer = dpkt.pcap.Writer(f_out, linktype=reader.datalink())

        for src_ip, dst_ip, proto, sport, dport, payload, raw_pkts in iter_sip_datagrams(reader, stats):
            if payload and is_sip(payload):
                cid_match = CALL_ID_RE.search(payload)
                if cid_match:
                    cid_val = cid_match.group(1).strip()
                    if len(seen_cids) < 10:
                        seen_cids.add(cid_val.decode("utf-8", errors="replace"))
                    if cid_val == target_bytes or target_bytes in cid_val:
                        for p_ts, p_buf in raw_pkts:
                            writer.writepkt(p_buf, ts=p_ts)
                            matched_packets += 1
                        first_line = payload.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                        flow_events.append((raw_pkts[0][0], src_ip, dst_ip, first_line))
                        rtp_endpoints.update(extract_sdp_endpoints(payload))
                        continue

            if proto == "UDP" and rtp_endpoints:
                if (src_ip, sport) in rtp_endpoints or (dst_ip, dport) in rtp_endpoints:
                    for p_ts, p_buf in raw_pkts:
                        writer.writepkt(p_buf, ts=p_ts)
                        matched_packets += 1

    print(f"Extracted {matched_packets} packets to {output_pcap}")
    if matched_packets == 0:
        print(f"\n[Diagnostics] datalink={stats['datalink']}, total={stats['total_packets']}, "
              f"ip={stats['ip_packets']}, fragments={stats['fragmented_packets']}, gtpu={stats['gtpu_packets']}")
        if seen_cids:
            print("Sample Call-IDs found in this PCAP:")
            for c in sorted(seen_cids):
                print(f"  - {c}")
        return

    print("\n--- Mermaid.js Call Flow ---")
    print("sequenceDiagram")
    start_ts = flow_events[0][0]
    for ts, src, dst, msg in flow_events:
        rel_ms = (ts - start_ts) * 1000
        print(f"    {src}->>{dst}: [{rel_ms:.1f}ms] {msg}")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[2] == "--list":
        list_calls(sys.argv[1])
    elif len(sys.argv) == 4:
        extract_call(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("Usage:")
        print("  python sip_extractor.py <input.pcap> --list")
        print("  python sip_extractor.py <input.pcap> <output.pcap> <call-id>")
        sys.exit(1)