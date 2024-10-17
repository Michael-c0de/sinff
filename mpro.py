import sys
import random
from PyQt5.QtCore import QAbstractTableModel, Qt, QThread, pyqtSignal, QVariant, QTimer
from PyQt5.QtWidgets import QApplication, QTableView, QVBoxLayout, QWidget, QMainWindow
from multiprocessing import Process, Queue
from sniffer import PacketDataView, select_device
from logger import logging, logger
logger.setLevel(logging.INFO)
class MyTableModel(QAbstractTableModel):
    def __init__(self, data, headers):
        super().__init__()
        self._data = data
        self._headers = headers

    def data(self, index, role=Qt.DisplayRole):
        if role == Qt.DisplayRole:
            return str(self._data[index.row()][index.column()])
        return QVariant()

    def rowCount(self, index):
        return len(self._data)

    def columnCount(self, index):
        return len(self._headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self._headers[section]
        return None

    def addRows(self, new_rows):
        """向模型中添加多行新数据"""
        start_row = self.rowCount(self.index(0, 0))  
        end_row = start_row + len(new_rows) - 1      
        self.beginInsertRows(self.index(0, 0).parent(), start_row, end_row)

        # 将字典转换为列表，每个字典项按顺序转换为列表的一行
        for row in new_rows:
            row_data = [
                row["ts"],    # 从字典提取出各列数据
                row["src1"],
                row["dst1"],
                row["src2"],
                row["dst2"],
                row["info"]
            ]
            self._data.append(row_data)  # 将转换后的行数据添加到模型的数据中

        self.endInsertRows()


# class DataThread(QThread):
#     new_data_signal = pyqtSignal(list)

#     def __init__(self, data_view: PacketDataView, data_queue: Queue):
#         super().__init__()
#         self.data_view = data_view
#         self.data_queue = data_queue  # 用于通信

#     def run(self):
#         while True:
#             new_data = self.data_view.get_new_list()
#             if new_data:
#                 self.data_queue.put(new_data)  # 通过队列发送数据到UI进程
#             self.sleep(2)  # 休眠2秒，减少资源占用




class DynamicTable(QWidget):
    def __init__(self, data_queue:Queue):
        super().__init__()
        self.data_queue = data_queue  # 获取队列对象
        self.initial_data = []
        headers = ["ts", "src1", "dst1", "src2", "dst2", "info"]
        self.model = MyTableModel([], headers)

        # 创建QTableView并设置模型
        self.table_view = QTableView()
        self.table_view.setModel(self.model)

        # 布局
        layout = QVBoxLayout()
        layout.addWidget(self.table_view)
        self.setLayout(layout)

        # 定时器，每0.5秒从队列获取数据
        self.update_timer = QTimer(self)
        self.update_timer.setInterval(500)  # 每0.5秒更新一次表格
        self.update_timer.timeout.connect(self.update_table)
        self.update_timer.start()

    
    def update_table(self):
        """定期检查数据队列并更新表格"""
        new_rows = []
        if not self.data_queue.empty():
            items = self.data_queue.qsize()
            for _ in range(items):
                new_rows.append(self.data_queue.get())  # 从队列中获取数据
            self.model.addRows(new_rows)  # 更新模型
            # self.table_view.scrollToBottom()  # 滚动到表格底部


# class MainWindow(QMainWindow):
#     """Qt主窗口，用于数据呈现和用户交互"""
#     def __init__(self, table: DynamicTable):
#         super().__init__()
#         self.setWindowTitle("Packet Sniffer")
#         self.setGeometry(100, 100, 800, 400)
#         self.setCentralWidget(table)


import time
import os
def data_process(item_queue:Queue, message:Queue, dev, bpf):
    # 启动抓包和数据更新
    data_view = PacketDataView(dev, item_queue, bpf)
    data_view.start_capture()
    # 保持子进程运行直到主进程发出停止信号
    while True:
        if not message.empty():
            if message.get() == "stop":
                data_view.close_capture()
                break
    # todo:检查子进程不退出的原因，这很奇怪
    os._exit(1)



def  test():
    dev = select_device()  # 选择设备

    
    item_queue = Queue()  # 创建进程间通信的队列
    message = Queue()  # 创建进程间通信的队列

    p = Process(target=data_process, args=(item_queue, message, dev, ""))
    p.daemon = True
    p.start()
    
    # 模拟一段时间的抓包
    time.sleep(3)  # 抓包10秒
    print("Stopping capture.")
    message.put("stop")
    p.join()
if __name__ == '__main__':


    dev = select_device()  # 选择设备

    
    item_queue = Queue()  # 创建进程间通信的队列
    message = Queue()  # 创建进程间通信的队列



    p = Process(target=data_process, args=(item_queue, message, dev, ""))
    p.daemon = True
    p.start()


    # 启动Qt应用
    app = QApplication(sys.argv)
    window = DynamicTable(item_queue)
    window.show()

    app.exec_()
    message.put("stop")

    p.join()

    # 运行Qt应用
    sys.exit()