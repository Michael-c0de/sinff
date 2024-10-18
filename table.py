import sys
from PyQt5.QtCore import QAbstractTableModel, Qt, QVariant, QTimer, QCoreApplication
from PyQt5.QtWidgets import QApplication, QTableView, QVBoxLayout,QHBoxLayout, QWidget, QMainWindow,QPushButton
from multiprocessing import Process, Queue
from sniffer import PacketDataView, select_device
from logger import logging, logger
from PyQt5.QtWidgets import QHeaderView
from PyQt5.QtGui import QDesktopServices
import time
import os
logger.setLevel(logging.DEBUG)

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


class DynamicTable(QWidget):
    def __init__(self, item_list:list, table_model:MyTableModel):
        super().__init__()
        self.item_list = item_list  # 已经分析的数据包信息
        self.model = table_model
        # 已经渲染了self.offset个数据包
        self.offset = 0
        # 创建QTableView并设置模型
        self.table_view = QTableView()
        self.table_view.setModel(self.model)
        
        # 设置列宽自适应内容
        header = self.table_view.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

        # 垂直布局
        layout = QVBoxLayout()
        layout.addWidget(self.table_view)
        self.setLayout(layout)

        # 定时器，每0.5秒从队列获取数据
        self.update_timer = QTimer(self)
        self.update_timer.setInterval(1000)  # 每1秒更新一次表格
        self.update_timer.timeout.connect(self.update_table)
        self.update_timer.start()

    def update_table(self):
        """定期检查数据队列并更新表格"""
        new_offset = len(self.item_list)
        if new_offset > self.offset:
            self.table_view.setUpdatesEnabled(False)
            self.model.addRows(self.item_list[self.offset:])  # 更新模型
            self.table_view.setUpdatesEnabled(True)
            logger.debug(f"update {new_offset - self.offset} packets end")
            self.offset = new_offset
            # self.table_view.scrollToBottom()  # 滚动到表格底部

    # def update_table(self):
    #     """定期检查数据队列并更新表格"""
    #     new_rows = []
    #     if not self.data_queue.empty():
    #         self.table_view.setUpdatesEnabled(False)
    #         items = self.data_queue.qsize()
    #         for _ in range(items):
    #             new_rows.append(self.data_queue.get())  # 从队列中获取数据
    #         self.model.addRows(new_rows)  # 更新模型
    #         self.table_view.setUpdatesEnabled(True)
    #         # self.table_view.scrollToBottom()  # 滚动到表格底部


class MainWindow(QMainWindow):
    """Qt主窗口，用于数据呈现和用户交互"""
    def __init__(self, table: DynamicTable):
        super().__init__()
        self.setGeometry(100, 100, 500, 400)
        self.showMaximized()

        # 创建主窗口中的中央控件，QMainWindow 需要设置中央控件
        self.setCentralWidget(table)





def data_process(item_queue:Queue, message:Queue, dev, bpf):
    # 启动抓包和数据更新
    data_view = PacketDataView(dev, item_queue, bpf, 0)
    data_view.start_capture()
    # 保持子进程运行直到主进程发出停止信号
    while True:
        if not message.empty():
            if message.get() == "stop":
                data_view.close_capture()
                break
    # todo:检查子进程不退出的原因，这很奇怪
    os._exit(1)




def test():
    dev = select_device()  # 选择设备

    
    item_queue = Queue()  # 创建进程间通信的队列
    message = Queue()  # 创建进程间通信的队列

    p = Process(target=data_process, args=(item_queue, message, dev, "udp"))
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
    message = Queue()
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