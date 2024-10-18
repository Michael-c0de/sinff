import libpcap as pcap
import ctypes as ct
import os
errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
PATH = b"tmp.pcap"
filename = ct.c_char_p(PATH)
handle = pcap.open_offline(filename, errbuf)

while True:
    res = os.stat(PATH)
    print(res.st_size)
    
