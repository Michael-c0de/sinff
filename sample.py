import sys
import threading
from collections import deque
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtCore import pyqtSignal, QObject
import libpcap as pcap
import ctypes as ct
from scapy.all import Ether
from device_mm import PcapDeviceManager
from PyQt5.QtCore import pyqtSlot, QTimer


class PacketCaptureThread(threading.Thread):
    """抓包线程"""
    def __init__(self, packet_queue:deque, dev, stop_event:threading.Event, bpf_exp='udp', max_count=4096):
        super().__init__()
        self.packet_queue = packet_queue
        self.dev = dev
        self.stop_event = stop_event
        self.bpf_exp = bpf_exp
        self.handle = None
        self.max_count = max_count
        self.ts0 = None
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
        result = pcap.loop(self.handle, self.max_count, PCAP_HANDLER(self.packet_handler), None)  # 逐包处理
        if result != pcap.PCAP_ERROR_BREAK :
            print(f"pcap loop exit: {result}")
        self.stop()
    
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
        if self.handle:
            pcap.breakloop(self.handle)
            pcap.close(self.handle)
            self.handle = None
            self.stop_event.set()
            print("PacketCaptureThread end")
            

class PacketAnalysisThread(threading.Thread):
    """数据分析线程"""
    def __init__(self, packet_queue:deque, result_queue:deque, stop_event:threading.Event):
        super().__init__()
        self.packet_queue = packet_queue
        self.result_queue = result_queue
        self.stop_event = stop_event

    def run(self):
        """线程运行函数，处理数据包并进行分析"""
        while not self.stop_event.is_set() or len(self.packet_queue)!=0:
            try:
                ts, packet_data = self.packet_queue.pop()
                # 解析数据包
                frame = Ether(packet_data)
                # 数据分析（此处为示例，实际逻辑可以更复杂）
                result = {
                    "ts":f"{ts:.6}",
                    "src1":frame.src,
                    "dst1":frame.dst,
                    "src2":frame.payload.src,
                    "dst2":frame.payload.dst,
                    "info":frame.summary()
                }
                self.result_queue.appendleft(result)  # 将分析结果放入结果队列
            except Exception as e:
                continue
        self.stop()
        print("PacketAnalysisThread end")

    def stop(self):
        """停止分析"""
        self.stop_event.set()

class SignalManager(QObject):
    """信号管理类，用于子线程和主线程通信"""
    result_signal = pyqtSignal(str)

class MainWindow(QMainWindow):
    """Qt主窗口，用于数据呈现和用户交互"""
    def __init__(self, result_queue:deque):
        super().__init__()
        self.result_queue = result_queue
        # 初始化UI
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 800, 400)

        # 设置主部件为一个表格，用于显示抓包信息
        self.table = QTableWidget(self)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ts", "src1", "dst1", "src2", "dst2", "info"])
        # 设置列宽自适应内容
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

        layout = QVBoxLayout()
        layout.addWidget(self.table)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        # 定时器定时刷新抓包数据
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_table)
        # 控制刷新速率，每秒200条
        self.timer.start(2000)  # 每秒刷新一次
        self.batch_size = 200

    @pyqtSlot()
    def update_table(self):
        """定时刷新抓包数据"""
        rows_to_insert = []
        while len(self.result_queue) > 0 and len(rows_to_insert) < self.batch_size:
            item = self.result_queue.pop()
            rows_to_insert.append(item)

        # 批量插入数据到表格，减少频繁的UI更新
        if rows_to_insert:
            self.table.setUpdatesEnabled(False)  # 暂停UI更新，提升性能
            for item in rows_to_insert:
                row_count = self.table.rowCount()
                self.table.insertRow(row_count)
                self.table.setItem(row_count, 0, QTableWidgetItem(item['ts']))
                self.table.setItem(row_count, 1, QTableWidgetItem(item['src1']))
                self.table.setItem(row_count, 2, QTableWidgetItem(item['dst1']))
                self.table.setItem(row_count, 3, QTableWidgetItem(item['src2']))
                self.table.setItem(row_count, 4, QTableWidgetItem(item['dst2']))
                self.table.setItem(row_count, 5, QTableWidgetItem(item['info']))

            self.table.setUpdatesEnabled(True)  # 重新启用UI更新
            self.table.scrollToBottom()  # 保持滚动条在底部

    # @pyqtSlot()
    # def update_table(self):
    #     """定时刷新抓包数据"""
    #     while len(self.result_queue)!=0:
    #         ts, result = self.result_queue.pop()
    #         row_count = self.table.rowCount()
    #         self.table.insertRow(row_count)
    #         self.table.setItem(row_count, 0, QTableWidgetItem(ts))
    #         self.table.setItem(row_count, 1, QTableWidgetItem(result))




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

    # 初始化 Qt 应用
    app = QApplication(sys.argv)
    main_window = MainWindow(result_queue)
    main_window.show()

    # 创建抓包线程和数据分析线程
    capture_thread = PacketCaptureThread(packet_queue, dev, stop_event, "")
    analysis_thread = PacketAnalysisThread(packet_queue, result_queue, stop_event)

    # 启动线程
    capture_thread.start()
    analysis_thread.start()

    # 启动应用
    app.exec_()


    # 停止线程
    capture_thread.stop()
    analysis_thread.stop()
    capture_thread.join()
    analysis_thread.join()



if __name__ == "__main__":
    main()
