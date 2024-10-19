import threading
from queue import Queue
import libpcap as pcap
import ctypes as ct
from scapy.all import Ether
from device_mm import PcapDeviceManager
from logger import  logger
import time
from util import copy_packet_pointer, copy_pkthdr_pointer

# import cProfile
# cProfile.run('PacketAnalysisThread.run()')

class PacketCaptureThread(threading.Thread):
    """抓包线程"""
    def __init__(self, packet_queue:Queue, handle ,max_count=4096):
        super().__init__()
        self.packet_queue = packet_queue
        self.max_count = max_count
        self.ts0 = None
        self.handle = handle
        self.setDaemon(True)
        self.count = 0
    


    def run(self):
        logger.info(f"PacketCapture Thread#{threading.get_ident()} run")
        """线程运行函数"""

        PCAP_HANDLER = ct.CFUNCTYPE(None, ct.POINTER(ct.c_ubyte), ct.POINTER(pcap.pkthdr), ct.POINTER(ct.c_ubyte))

        start_time = time.time()
        # 时间检测
        result = pcap.loop(self.handle, self.max_count, PCAP_HANDLER(self.packet_handler), None)  # 逐包处理
        end_time = time.time()

        if result != pcap.PCAP_ERROR_BREAK :
            logger.info(f"pcap loop exit: {result}")
        self.packet_queue.put(("end","end"))
        logger.info(f"PacketCapture Thread#{threading.get_ident()} end")
        logger.info(f"Captured {self.count} packets in {end_time - start_time:.2f} seconds")
        

    def packet_handler(self, _,  _pkthdr, _packet):
        """
        处理抓到的包，放入队列
        _pkthdr:ct.POINTER(pcap.pkthdr)
        _packet:ct.POINTER(ct.c_ubyte)
        """
        
        # ct.POINTER(pkthdr), ct.POINTER(ct.c_ubyte)
        # print("hint")
        caplen = _pkthdr.contents.caplen
        # print(caplen)
        pkthdr = copy_pkthdr_pointer(_pkthdr)
        packet = copy_packet_pointer(_packet, caplen)
        # logger.info(f"#{self.count}, {caplen}")
        self.count+=1
        # pcap.dump(self.out_pcap, pkthdr, packet)
        # pcap.dump_flush(args)
        # self.packet_queue()
        
        # packet = bytes(_packet[:])
        
        # _ts = pkthdr.contents.ts
        # ts = _ts.tv_sec + (_ts.tv_usec/1000000)
        # if self.ts0 == None:
        #     self.ts0 = ts
        # ts = ts - self.ts0
        # if len(self.packet_queue) < self.packet_queue.maxlen:
        self.packet_queue.put((pkthdr, packet))  # 将原始数据包放入队列
        # logger.debug(f"PacketCapture {pkthdr[0].caplen}")

    def stop(self):
        pcap.breakloop(self.handle)

from queue import Queue
class PacketAnalysisThread(threading.Thread):
    """
    数据分析线程
    pcap_out:ct.POINTER(ct.c_ubyte)
    """
    def __init__(self, packet_queue:Queue, frame_items:Queue, pcap_out_dt):
        super().__init__()
        # 入队
        self.packet_queue = packet_queue
        # 出队
        self.frame_items = frame_items

        self.out_dt = pcap_out_dt
        self.out_ub = ct.cast(self.out_dt, ct.POINTER(ct.c_ubyte))
        self.ts = None
        self.setDaemon(True)
        
    def run(self):
        logger.info(f"PacketAnalysis Thread#{threading.get_ident()} run")
        """线程运行函数，处理数据包并进行分析"""
        while True:
            try:
                pkthdr, packet = self.packet_queue.get()
                if(pkthdr=="end"):
                    print("a"*1000)
                    break
                # 解析数据包
                # logger.debug(f"PacketAnalysis {pkthdr[0].caplen}")
                # print(pkthdr[0].caplen)
                frame = Ether(bytes(packet[:pkthdr[0].caplen]))
                # 记录到磁盘
                pcap.dump(self.out_ub, pkthdr, packet)
                # 计算时间戳
                pk_ts = pkthdr[0].ts.tv_sec + pkthdr[0].ts.tv_usec/1000000
                if self.ts is None:
                    self.ts = pk_ts
                pk_ts -= self.ts
                self.frame_items.put((pk_ts, frame))
            except Exception as e:
                logger.warning(e)
                continue
        self.stop()
        # logger.info(f"PacketAnalysis Thread#{threading.get_ident()} end")
        

    def stop(self):
        """停止分析"""
        
        pcap.dump_flush(self.out_dt)
        pcap.dump_close(self.out_dt)
        


class PacketDataView():
    """数据查询接口"""
    def __init__(self, dev, item_queue:Queue, bpf_exp, max_count = 0, tmpfile="tmp.pcap"):
        self.table_items = item_queue
        # 队列长度
        self._packet_queue = Queue()
        self.dev = dev
        self.bpf_exp = bpf_exp
        self.max_count = max_count
        self.last_index = 0

        errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        self.handle = pcap.open_live(self.dev, 4096, 1, -1, errbuf)
        if not self.handle:
            raise RuntimeError(f"Error opening device: {errbuf.value.decode()}")
        self.out_dt = pcap.dump_open(self.handle, ct.c_char_p(tmpfile.encode()))
        self.out_ub = ct.cast(self.out_dt, ct.POINTER(ct.c_ubyte))
        self.set_bpf_filter()
        


    def set_bpf_filter(self):
        """设置 BPF 过滤器"""
        fp = pcap.bpf_program()
        net = pcap.bpf_u_int32()
        if pcap.compile(self.handle, fp, self.bpf_exp.encode(), 0, net) == -1:
            raise RuntimeError(pcap.geterr(self.handle).decode())
        if pcap.setfilter(self.handle, fp) == -1:
            raise RuntimeError(pcap.geterr(self.handle).decode())
        logger.info(f"BPF filter '{self.bpf_exp}' set successfully.")
    
    def start_capture(self):
        self.last_index = 0

        self._stop_event = threading.Event()
        self._capture_thread = PacketCaptureThread(self._packet_queue, self.handle, self.max_count)
        self._analysis_thread = PacketAnalysisThread(self._packet_queue, self.table_items, self.out_dt)
        self._capture_thread.start()
        self._analysis_thread.start()

    def close_capture(self):
        self._capture_thread.stop()        
        # 数据分析线程不必阻塞
        # self._analysis_thread.stop()
        self._capture_thread.join()
        self._analysis_thread.join()
        pcap.close(self.handle)


    def get_new_list(self):
        data = self.table_items[self.last_index:]
        self.last_index = len(self.table_items)
        logger.debug(f"Show #{len(data)} frame items")
        return data
    
    def get_table_item(self, index):
        return self.table_items[index]
    



def select_device():
    """选择设备"""
    manager = PcapDeviceManager()
    manager.find_all_devices()    
    devices_info = manager.list_devices()
    for id, description, ip in devices_info:
        print(f"#{id}, {description}, {ip}")    
    a  = int(input("Please select a device: "))
    device = manager.get_device(a)
    return device


def main():
    dev = select_device()
    data_view = PacketDataView(dev, "")
    # 创建抓包线程和数据分析线程

    while(1):
        data_view.start_capture()
        # 启动应用
        while(1):
            for item in data_view.get_new_list():
                # print(f"{item}")
                if data_view.last_index>100:
                    break
            if data_view.last_index>100:
                break
        data_view.close_capture()

if __name__ == "__main__":
    main()
