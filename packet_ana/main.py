from scapy.all import *
def hexdump_bytes(data):
    result = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f"{byte:02x}" for byte in chunk)
        ascii_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
        result.append(f"{i:08x}  {hex_part:<47}  {ascii_part}")
    return '\n'.join(result)

def get_field(packet:Packet):
    display = {}
    p = packet
    while p:
        display[p.name] = p.fields
        p = p.payload
    return display

pcap = rdpcap("../data.pcap")

for p in pcap:
    p.display()