from scapy.all import rdpcap

# 读取 pcap 文件
packets = rdpcap('tmp.pcap')

# 遍历每个数据包并打印 summary
for packet in packets:
    print(packet.summary())
