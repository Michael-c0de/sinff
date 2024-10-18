import libpcap as pcap
import ctypes as ct
# 深拷贝 pkthdr 结构体
def copy_pkthdr_pointer(_pkthdr):
    # 创建新的 pkthdr 对象，并复制字段
    new_pkthdr = pcap.pkthdr()
    ct.pointer(new_pkthdr)[0] = _pkthdr.contents  # 深拷贝结构体
    return ct.pointer(new_pkthdr)  # 返回新的指针

# 深拷贝 ct.POINTER(ct.c_ubyte) 类型的指针数据
def copy_packet_pointer(_packet, length):
    # 创建新的缓冲区，并将原始数据拷贝到新的缓冲区
    new_packet = (ct.c_ubyte * length)()  # 创建新的数组
    ct.memmove(new_packet, _packet, length)  # 深拷贝原始数据
    return ct.cast(new_packet, ct.POINTER(ct.c_ubyte))  # 返回新的指针