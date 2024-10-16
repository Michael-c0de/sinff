from scapy.all import rdpcap, Ether, IP, TCP, UDP

# 读取 .pcap 文件
packets = rdpcap('data.pcap')

# 遍历并解析每个数据包
for pkt in packets:
    pkt.summary()
    break
