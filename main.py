import sys
import threading
from scapy.all import sniff
from PyQt5.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget
from PyQt5.QtCore import pyqtSlot, QTimer
from sniff import PcapSniffer

class PacketSnifferShow(QMainWindow, PcapSniffer):
    def __init__(self):
        super().__init__()

        # 设置窗口标题和大小
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 800, 400)

        # 设置主部件为一个表格，用于显示抓包信息
        self.table = QTableWidget(self)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Source IP", "Destination IP", "Protocol"])

        layout = QVBoxLayout()
        layout.addWidget(self.table)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # 定时器定时刷新抓包数据
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_table)
        self.timer.start(1000)  # 每秒刷新一次

        # 用于存储捕获的数据包
        self.packet_list = []

        # # 启动抓包线程
        # self.sniff_thread = threading.Thread(target=self.start_sniffing)
        # self.sniff_thread.daemon = True
        # self.sniff_thread.start()

    def start_sniffing(self):
        """启动抓包线程"""
        sniff(prn=self.process_packet)

    def process_packet(self, packet):
        """处理抓到的数据包"""
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            proto = packet["IP"].proto
            # 将数据添加到 packet_list 中
            self.packet_list.append((src_ip, dst_ip, proto))

    @pyqtSlot()
    def update_table(self):
        """定时刷新抓包数据"""
        self.table.setRowCount(len(self.packet_list))
        for row, packet_data in enumerate(self.packet_list):
            src_ip, dst_ip, proto = packet_data
            self.table.setItem(row, 0, QTableWidgetItem(src_ip))
            self.table.setItem(row, 1, QTableWidgetItem(dst_ip))
            self.table.setItem(row, 2, QTableWidgetItem(self.get_protocol_name(proto)))

    def get_protocol_name(self, proto):
        """返回协议名称"""
        if proto == 6:
            return "TCP"
        elif proto == 17:
            return "UDP"
        elif proto == 1:
            return "ICMP"
        else:
            return str(proto)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferShow()
    window.show()
    sys.exit(app.exec_())


# export CONDA_EXE="$(cygpath -u 'D:\Users\16795\anaconda3\Scripts\conda.exe' | sed 's|/cygdrive||')"
