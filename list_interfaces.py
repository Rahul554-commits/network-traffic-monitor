from scapy.all import get_if_list, get_if_addr

print("Available Interfaces with IPs:\n")
for i, iface in enumerate(get_if_list()):
    try:
        print(f"[{i}] {iface} -> {get_if_addr(iface)}")
    except:
        print(f"[{i}] {iface} -> No IP")
