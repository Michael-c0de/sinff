import sys
import random
from PyQt5.QtCore import QAbstractTableModel, Qt, QTimer, QThread, pyqtSignal, QVariant
from PyQt5.QtWidgets import QApplication, QTableView, QVBoxLayout, QWidget, QMainWindow
from sniffer import PacketDataView, select_device

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


class DataThread(QThread):
    
    new_data_signal = pyqtSignal(list)

    def __init__(self, data_view:PacketDataView):
        super().__init__()
        self.data_view = data_view

    def run(self):
        while True:
            new_data = self.data_view.get_new_list()
            if new_data:
                self.new_data_signal.emit(new_data)  # 发射新数据的信号
            self.sleep(2)  # 休眠2秒

class DynamicTable(QWidget):
    def __init__(self, data_view):
        super().__init__()
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

        # 启动数据线程
        self.data_thread = DataThread(data_view)
        self.data_thread.new_data_signal.connect(self.add_data_to_buffer)
        self.data_thread.start()

        # 使用定时器定期更新UI
        self.update_timer = QTimer(self)
        self.update_timer.setInterval(2000)  # 每2秒更新一次表格
        self.update_timer.timeout.connect(self.update_table)
        self.update_timer.start()

        self.new_rows_buffer = []  # 用于缓存新数据

    def add_data_to_buffer(self, new_rows):
        """将新数据加入缓存"""
        self.new_rows_buffer.extend(new_rows)

    def update_table(self):
        """定期更新表格"""
        if self.new_rows_buffer:
            # 禁用UI更新以提高性能
            self.table_view.setUpdatesEnabled(False)

            # 批量更新数据
            self.model.addRows(self.new_rows_buffer)
            self.table_view.scrollToBottom()  # 滚动条保持在底部

            # 清空缓存
            self.new_rows_buffer.clear()
            # 恢复UI更新
            self.table_view.setUpdatesEnabled(True)



class MainWindow(QMainWindow):
    """Qt主窗口，用于数据呈现和用户交互"""
    def __init__(self, table: DynamicTable):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 800, 400)
        self.setCentralWidget(table)


if __name__ == '__main__':

    dev = select_device()
    data_view = PacketDataView(dev, "")
    app = QApplication(sys.argv)
    table = DynamicTable(data_view)
    window = MainWindow(table)
    data_view.start_capture()
    window.show()
    sys.exit(app.exec_())