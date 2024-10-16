import libpcap as pcap
import ctypes as ct
import signal
from scapy.all import Ether
from device_mm import PcapDeviceManager
# from queue import Queue
from collections import deque

import threading
import time
class PcapSniffer:
    def __init__(self, packet_queue_size=1425328):
        self.handle = None
        self.packet_queue = deque(maxlen=packet_queue_size)  # 创建队列
        self.running = False  # 标志捕获是否在运行
        self.packet_handler_thread = None
        self.count=0
    def select_device(self):
        """选择设备"""
        manager = PcapDeviceManager()
        manager.find_all_devices()    
        devices_info = manager.list_devices()
        for id, description, ip in devices_info:
            print(f"#{id}, {description}, {ip}")    
        a  = int(input("Please select a device: "))
        device = manager.get_device(a)
        return device

    def packet_capture(self, user, pkthdr, packet):

        """捕获数据包的回调函数，将数据包放入队列"""
        raw_data = bytes(packet[:pkthdr.contents.caplen])
        if len(self.packet_queue) < self.packet_queue.maxlen:
            self.packet_queue.append(raw_data)
        else:
            print("Queue is full, dropping packet.")
    def signal_handler(self, signum, frame):
        """捕获 Ctrl+C 信号，停止数据包捕获"""
        print("User entered Ctrl+C, stopping capture...")
        if self.handle:
            pcap.breakloop(self.handle)
        self.running = False

    def set_bpf_filter(self, filter_exp):
        """设置 BPF 过滤器"""
        fp = pcap.bpf_program()
        net = pcap.bpf_u_int32()
        if pcap.compile(self.handle, fp, filter_exp.encode(), 0, net) == -1:
            raise RuntimeError(pcap.geterr(self.handle).decode())
        if pcap.setfilter(self.handle, fp) == -1:
            raise RuntimeError(pcap.geterr(self.handle).decode())
        print(f"BPF filter '{filter_exp}' set successfully.")

    def start_capture(self, dev, filter_exp="udp", packet_count=100000):
        """启动数据包捕获"""
        # 打开设备进行捕获
        errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        self.handle = pcap.open_live(dev, 4096, 1, -1, errbuf)

        if not self.handle:
            raise RuntimeError(f"Error opening device: {errbuf.value.decode()}")

        # 设置信号处理
        signal.signal(signal.SIGINT, self.signal_handler)

        # 设置 BPF 过滤器
        self.set_bpf_filter(filter_exp)

        # 开始捕获数据包
        PCAP_HANDLER = ct.CFUNCTYPE(None, ct.POINTER(ct.c_ubyte), ct.POINTER(pcap.pkthdr), ct.POINTER(ct.c_ubyte))
        print(f"Starting packet capture on {dev} with filter '{filter_exp}'")
        self.running = True
        self.packet_handler_thread = threading.Thread(target=self.process_packets)
        self.packet_handler_thread.start()  # 启动数据包处理线程
        
        # 开始计时
        start_time = time.time()
        result = pcap.loop(self.handle, packet_count, PCAP_HANDLER(self.packet_capture), None)
        # 结束计时
        end_time = time.time()
        if result == -1:
            print("Error during packet capture")
        else:
            print("Packet capture finished")
        # 打印捕获 1000 个数据包的耗时
        elapsed_time = end_time - start_time
        print(f"Captured {packet_count} packets in {elapsed_time:.2f} seconds. #count = {self.count}")
        # 关闭句柄
        pcap.close(self.handle)
        self.running = False
        
    def process_packets(self):
        while self.running or len(self.packet_queue)!=0:
            try:
                packet_data = self.packet_queue.pop()  # 从队列中获取数据包
                frame = Ether(packet_data)
                print(frame.summary())
            except Exception as e:
                continue  # 队列为空时继续等待数据包

    def stop_capture(self):
        """手动停止捕获"""
        if self.handle:
            pcap.breakloop(self.handle)
            pcap.close(self.handle)
        self.running = False

if __name__ == "__main__":
    sniffer = PcapSniffer()
    
    # 选择设备
    dev = sniffer.select_device()

    # 启动数据包捕获，默认捕获 TCP 包
    sniffer.start_capture(dev, filter_exp="udp")


