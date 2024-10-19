
from scapy.all import *
pcap = rdpcap("./tmp.pcap")

for p in pcap:
    p.display()