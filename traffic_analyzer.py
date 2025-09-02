# traffic_analyzer.py
"""
Network Traffic Analyzer (Windows-friendly)
Captures packets using Scapy, logs them to CSV, and prints live stats.
Run as Administrator: python traffic_analyzer.py
"""

import csv
import os
from datetime import datetime
from collections import Counter

from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list

LOG_FILE = "packets.csv"
proto_counter = Counter()
talkers = Counter()
total = 0

# Write header if file does not exist
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src", "dst", "proto", "sport", "dport", "length"])


def parse_packet(pkt):
    """Extract fields from packet"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    src, dst, proto, sport, dport = "N/A", "N/A", "OTHER", "", ""

    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst

    if TCP in pkt:
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    elif ICMP in pkt:
        proto = "ICMP"

    length = len(pkt)
    return ts, src, dst, proto, sport, dport, length


def handle_packet(pkt):
    """Process packet: log + stats"""
    global total
    ts, src, dst, proto, sport, dport, length = parse_packet(pkt)
    total += 1
    proto_counter[proto] += 1
    talkers[src] += 1

    # Print one-line summary
    print(f"[{ts}] {src}:{sport} -> {dst}:{dport} {proto} {length}B")

    # Append to CSV
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([ts, src, dst, proto, sport, dport, length])


def main():
    ifaces = get_if_list()
    print("Available interfaces:")
    for i, iface in enumerate(ifaces):
        print(f"[{i}] {iface}")

    idx = int(input("Select interface index: "))
    iface = ifaces[idx]

    print(f"\n[STARTING] Listening on {iface} ... Press Ctrl+C to stop.")
    try:
        sniff(iface=iface, prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\n[STOPPED]")
        print(f"Total packets: {total}")
        print("Protocol counts:", dict(proto_counter))
        print("Top talkers:", talkers.most_common(5))


if __name__ == "__main__":
    main()
