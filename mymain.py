# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QApplication

import sys
from table import data_process, DynamicTable
from sniffer import select_device
from multiprocessing import Process, Queue

class Ui_Form(object):
    def setupUi(self, Form, data_queue):
        Form.setObjectName("Form")
        # Use a vertical layout for the main form
        main_layout = QtWidgets.QVBoxLayout(Form)

        self.splitter_2 = QtWidgets.QSplitter(Form)
        self.splitter_2.setOrientation(QtCore.Qt.Vertical)
        self.splitter_2.setObjectName("splitter_2")

        # Replace QTableView with DynamicTable
        self.dynamic_table = DynamicTable(data_queue)
        self.dynamic_table.setObjectName("dynamicTable")

        # Use a horizontal splitter for the text browsers
        self.splitter = QtWidgets.QSplitter(self.splitter_2)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName("splitter")

        self.textBrowser = QtWidgets.QTextBrowser(self.splitter)
        self.textBrowser.setObjectName("textBrowser")
        self.textBrowser.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

        self.textBrowser_2 = QtWidgets.QTextBrowser(self.splitter)
        self.textBrowser_2.setObjectName("textBrowser_2")
        self.textBrowser_2.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

        # Add the splitter to the main layout
        main_layout.addWidget(self.splitter_2)
        # Add widgets to the splitter
        self.splitter_2.addWidget(self.dynamic_table)
        self.splitter_2.addWidget(self.splitter)

        self.splitter.addWidget(self.textBrowser)
        self.splitter.addWidget(self.textBrowser_2)

        # Set the stretch factors to allow height adjustment
        self.splitter.setSizes([1, 1])  # Equal space for text browsers

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))



# 数据逻辑应该被迁移到这里
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, item_queue):
        super().__init__()

        # Create the Form UI
        self.form_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.form_widget)
        self.ui = Ui_Form()
        self.ui.setupUi(self.form_widget, item_queue)

        # Set up the menu bar
        self.setupMenu()

        # Maximize the form
        self.showMaximized()

    def setupMenu(self):
        # Create a menu bar
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")
        
        # Adding actions to the File menu
        exit_action = QtWidgets.QAction("Exit", self)
        exit_action.triggered.connect(self.close)  # Close the application
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("Edit")
        
        # Additional edit actions can be added here
        # Example: edit_action = QtWidgets.QAction("Edit Item", self)
        # edit_menu.addAction(edit_action)

# def main():
#     app = QtWidgets.QApplication(sys.argv)
#     Form = QtWidgets.QWidget()
#     ui = Ui_Form()
#     ui.setupUi(Form)
#     # Maximize the form
#     Form.showMaximized()
    
#     sys.exit(app.exec_())


if __name__ == "__main__":
    dev = select_device()  # 选择设备
    item_queue = Queue()  # 创建进程间通信的队列
    message = Queue()
    p = Process(target=data_process, args=(item_queue, message, dev, ""))
    # p.daemon = True
    p.start()

    # 启动Qt应用
    app = QApplication(sys.argv)
    window = MainWindow(item_queue)
    window.show()

    app.exec_()
    message.put("stop")

    p.join()

    # 运行Qt应用
    sys.exit()
