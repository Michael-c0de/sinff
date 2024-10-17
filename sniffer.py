import threading
from collections import deque
import libpcap as pcap
import ctypes as ct
from scapy.all import Ether
from device_mm import PcapDeviceManager
from logger import logging, logger
logger.setLevel(logging.DEBUG)
class PacketCaptureThread(threading.Thread):
    """抓包线程"""
    def __init__(self, packet_queue:deque, dev, stop_event:threading.Event, bpf_exp='udp', max_count=4096):
        super().__init__()
        self.packet_queue = packet_queue
        self.dev = dev
        self.bpf_exp = bpf_exp
        self.stop_event = stop_event
        self.handle = None
        self.max_count = max_count
        self.ts0 = None
        self.setDaemon(True)
    
    def set_bpf_filter(self):
        """设置 BPF 过滤器"""
        fp = pcap.bpf_program()
        net = pcap.bpf_u_int32()
        if pcap.compile(self.handle, fp, self.bpf_exp.encode(), 0, net) == -1:
            raise RuntimeError(pcap.geterr(self.handle).decode())
        if pcap.setfilter(self.handle, fp) == -1:
            raise RuntimeError(pcap.geterr(self.handle).decode())
        logger.info(f"BPF filter '{self.bpf_exp}' set successfully.")
    
    def run(self):
        logger.info(f"PacketCapture Thread#{threading.get_ident()} run")
        """线程运行函数"""
        errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        self.handle = pcap.open_live(self.dev, 4096, 1, -1, errbuf)

        if not self.handle:
            raise RuntimeError(f"Error opening device: {errbuf.value.decode()}")
        self.set_bpf_filter()
        logger.info(f"Starting packet capture on {self.dev}")
        
        PCAP_HANDLER = ct.CFUNCTYPE(None, ct.POINTER(ct.c_ubyte), ct.POINTER(pcap.pkthdr), ct.POINTER(ct.c_ubyte))
        
        # 时间检测
        result = pcap.loop(self.handle, self.max_count, PCAP_HANDLER(self.packet_handler), None)  # 逐包处理
        if result != pcap.PCAP_ERROR_BREAK :
            logger.info(f"pcap loop exit: {result}")
        pcap.close(self.handle)
        logger.info(f"PacketCapture Thread#{threading.get_ident()} end")

    def packet_handler(self, _, pkthdr, packet):
        """处理抓到的包，放入队列"""
        raw_data = bytes(packet[:pkthdr.contents.caplen])
        _ts = pkthdr.contents.ts
        ts = _ts.tv_sec + (_ts.tv_usec/1000000)
        if self.ts0 == None:
            self.ts0 = ts
        ts = ts - self.ts0
        if len(self.packet_queue) < self.packet_queue.maxlen:
            self.packet_queue.appendleft((ts, raw_data))  # 将原始数据包放入队列
    
    def stop(self):
        pcap.breakloop(self.handle)
        self.stop_event.set()

from queue import Queue
class PacketAnalysisThread(threading.Thread):
    """数据分析线程"""
    def __init__(self, packet_queue:deque, table_items:Queue, packet_items:list, stop_event:threading.Event):
        super().__init__()
        self.packet_queue = packet_queue
        self.table_items = table_items
        self.packet_items = packet_items
        self.stop_event = stop_event
        self.setDaemon(True)

    def run(self):
        logger.info(f"PacketAnalysis Thread#{threading.get_ident()} run")
        """线程运行函数，处理数据包并进行分析"""
        while not self.stop_event.is_set() or len(self.packet_queue)!=0:
            try:
                ts, packet_data = self.packet_queue.pop()
                # 解析数据包
                frame = Ether(packet_data)
                # 数据分析
                result = {
                    "ts":f"{ts:.6}",
                    "src1":frame.src,
                    "dst1":frame.dst,
                    "src2":frame.payload.src,
                    "dst2":frame.payload.dst,
                    "info":frame.summary()
                }
                # 将分析结果放入结果列表
                logger.debug(f"put {result} in table_items")
                self.table_items.put(result)
                self.packet_items.append(packet_data)
            except Exception as e:
                continue
        self.stop()
        logger.info(f"PacketAnalysis Thread#{threading.get_ident()} end")

    def stop(self):
        """停止分析"""
        self.stop_event.set()
        

from queue import Queue
class PacketDataView():
    """数据查询接口"""
    def __init__(self, dev, item_queue:Queue, bpf_exp, max_count = 0):
        self.table_items = item_queue
        self.packet_list = []
        self._packet_queue = deque(maxlen=1000000)
        self.dev = dev
        self.bpf_exp = bpf_exp
        self.max_count = max_count
        self.last_index = 0
    def start_capture(self):
        self.last_index = 0
        self.packet_list.clear()
        self._packet_queue.clear()

        self._stop_event = threading.Event()
        self._capture_thread = PacketCaptureThread(self._packet_queue, self.dev, self._stop_event, self.bpf_exp, self.max_count)
        self._analysis_thread = PacketAnalysisThread(self._packet_queue, self.table_items, self.packet_list, self._stop_event)
        self._capture_thread.start()
        self._analysis_thread.start()

    def close_capture(self):
        self._capture_thread.stop()
        self._analysis_thread.stop()
        self._capture_thread.join()
        self._analysis_thread.join()
        

    def get_new_list(self):
        data = self.table_items[self.last_index:]
        self.last_index = len(self.table_items)
        logger.debug(f"Show #{len(data)} frame items")
        return data
    
    def get_table_item(self, index):
        return self.table_items[index]
    
    def get_packet(self, index):
        return self.packet_list[index]


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
