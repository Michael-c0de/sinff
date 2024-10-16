import sys
import threading
from collections import deque
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
from PyQt5.QtCore import pyqtSignal, QObject
import libpcap as pcap
import ctypes as ct
from scapy.all import Ether
from device_mm import PcapDeviceManager
import sched
import time

class PacketCaptureThread(threading.Thread):
    """抓包线程"""
    def __init__(self, packet_queue:deque, dev, bpf_exp='udp'):
        super().__init__()
        self.packet_queue = packet_queue
        self.dev = dev
        self.bpf_exp = bpf_exp
        self.handle = None
        self.setDaemon(True)

    def set_bpf_filter(self):
        """设置 BPF 过滤器"""
        fp = pcap.bpf_program()
        net = pcap.bpf_u_int32()
        if pcap.compile(self.handle, fp, self.bpf_exp.encode(), 0, net) == -1:
            raise RuntimeError(pcap.geterr(self.handle).decode())
        if pcap.setfilter(self.handle, fp) == -1:
            raise RuntimeError(pcap.geterr(self.handle).decode())
        print(f"BPF filter '{self.bpf_exp}' set successfully.")
    
    def run(self):
        """线程运行函数"""
        errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE + 1)
        self.handle = pcap.open_live(self.dev, 4096, 1, -1, errbuf)

        if not self.handle:
            raise RuntimeError(f"Error opening device: {errbuf.value.decode()}")
        self.set_bpf_filter()
        print(f"Starting packet capture on {self.dev}")
        
        PCAP_HANDLER = ct.CFUNCTYPE(None, ct.POINTER(ct.c_ubyte), ct.POINTER(pcap.pkthdr), ct.POINTER(ct.c_ubyte))
        
        # 时间检测
        result = pcap.loop(self.handle, 0, PCAP_HANDLER(self.packet_handler), None)  # 逐包处理
        if result != pcap.PCAP_ERROR_BREAK :
            print(f"pcap loop exit: {result}")
        pcap.close(self.handle)
        print("PacketCaptureThread end")
    
    def packet_handler(self, user, pkthdr, packet):
        """处理抓到的包，放入队列"""
        raw_data = bytes(packet[:pkthdr.contents.caplen])
        if len(self.packet_queue) < self.packet_queue.maxlen:
            self.packet_queue.append(raw_data)  # 将原始数据包放入队列
    def stop(self):
        if self.handle:
            pcap.breakloop(self.handle)

class PacketAnalysisThread(threading.Thread):
    """数据分析线程"""
    def __init__(self, packet_queue:deque, result_queue:deque, stop_event):
        super().__init__()
        self.packet_queue = packet_queue
        self.result_queue = result_queue
        self.stop_event = stop_event
        self.count = 0

    def run(self):
        """线程运行函数，处理数据包并进行分析"""
        while not self.stop_event.is_set():
            try:
                packet_data = self.packet_queue.pop()
                # 解析数据包
                frame = Ether(packet_data)
                # 数据分析（此处为示例，实际逻辑可以更复杂）
                result = f"Packet Summary: {frame.summary()}"
                print(f"#{self.count}, {result}")
                self.count+=1
                self.result_queue.append(result)  # 将分析结果放入结果队列
            except Exception as e:
                continue
        self.stop()
    def stop(self):
        """停止分析"""
        print("PacketAnalysisThread end")

class SignalManager(QObject):
    """信号管理类，用于子线程和主线程通信"""
    result_signal = pyqtSignal(str)

class MainWindow(QMainWindow):
    """Qt主窗口，用于数据呈现和用户交互"""
    def __init__(self, result_queue:deque, signal_manager, stop_event):
        super().__init__()
        self.result_queue = result_queue
        self.signal_manager = signal_manager
        self.stop_event = stop_event
        # 初始化UI
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 600, 400)
        layout = QVBoxLayout()

        self.label = QLabel("Packet Data:")
        layout.addWidget(self.label)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        # 连接信号槽，更新UI
        self.signal_manager.result_signal.connect(self.update_ui)
        self.scheduler = sched.scheduler(time.time, time.sleep)
        
        self.scheduler.enter(1, 1, self.poll_results)
        timer = threading.Thread(target=lambda:self.scheduler.run())
        timer.start()
    
    def update_ui(self, packet_summary):
        """更新UI，显示分析结果"""
        self.label.setText(packet_summary)

    def poll_results(self):
        if not self.stop_event.is_set():
            try:
                while len(self.result_queue)!=0:
                    result = self.result_queue.pop()
                    self.signal_manager.result_signal.emit(result)
            except Exception as e:
                print(f"poll_results err {e}")
                pass
            self.scheduler.enter(1, 1, self.poll_results)

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
    # 创建队列和线程停止事件
    packet_queue = deque(maxlen=1000000)
    result_queue = deque(maxlen=1000000)
    stop_event = threading.Event()

    # 创建信号管理器
    signal_manager = SignalManager()

    # 初始化 Qt 应用
    app = QApplication(sys.argv)
    main_window = MainWindow(result_queue, signal_manager, stop_event)
    main_window.show()

    # 创建抓包线程和数据分析线程
    capture_thread = PacketCaptureThread(packet_queue, dev, "udp")
    analysis_thread = PacketAnalysisThread(packet_queue, result_queue, stop_event)

    # 启动线程
    capture_thread.start()
    analysis_thread.start()

    # 启动应用
    app.exec_()
    capture_thread.stop()
    analysis_thread.stop()

    # 停止线程
    stop_event.set()
    capture_thread.join()
    analysis_thread.join()



if __name__ == "__main__":
    main()
