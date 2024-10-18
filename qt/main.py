import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel

# 创建一个主窗口类，继承自 QMainWindow
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("PyQt5 布局示例")  # 设置窗口标题

        # 创建主窗口中的中央控件，QMainWindow 需要设置中央控件
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        # 创建垂直布局管理器
        vbox_layout = QVBoxLayout()

        # 创建标签控件并添加到布局中
        label = QLabel("这是一个标签")
        vbox_layout.addWidget(label)

        # 创建水平布局管理器
        hbox_layout = QHBoxLayout()

        # 创建两个按钮，并添加到水平布局中
        button1 = QPushButton("按钮 1")
        button2 = QPushButton("按钮 2")
        hbox_layout.addWidget(button1)
        hbox_layout.addWidget(button2)

        # 将水平布局添加到垂直布局中
        vbox_layout.addLayout(hbox_layout)

        # 将布局设置为中央控件的布局
        central_widget.setLayout(vbox_layout)

# 创建应用程序对象
app = QApplication(sys.argv)

# 创建主窗口
window = MainWindow()
window.show()

# 进入应用程序的事件循环
sys.exit(app.exec_())