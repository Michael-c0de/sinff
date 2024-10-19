from PyQt5.QtWidgets import QApplication, QTreeView, QWidget, QVBoxLayout
from PyQt5.QtGui import  QStandardItemModel, QStandardItem
class DictTree(QWidget):
    def __init__(self, data_dict):
        super().__init__()
        self.data_dict = data_dict
        self.init_ui()

    def init_ui(self):
        self.tree_view = QTreeView()
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['Key', 'Value'])

        # 渲染字典
        self.populate_tree(self.model.invisibleRootItem(), self.data_dict)
        
        self.tree_view.setModel(self.model)
        
        layout = QVBoxLayout()
        layout.addWidget(self.tree_view)
        self.setLayout(layout)

    def populate_tree(self, parent, dictionary):
        """递归渲染嵌套字典"""
        for key, value in dictionary.items():
            key_item = QStandardItem(str(key))
            if isinstance(value, dict):
                value_item = QStandardItem("Dictionary")
                parent.appendRow([key_item, value_item])
                self.populate_tree(key_item, value)
            else:
                value_item = QStandardItem(str(value))
                parent.appendRow([key_item, value_item])

# 示例嵌套字典
nested_dict = {'Ethernet': {'dst': '01:00:5e:00:00:fb',
  'src': '62:1d:e2:93:6e:1a',
  'type': 2048},
 'IP': {'version': 4,
  'ihl': 5,
  'tos': 0,
  'len': 423,
  'id': 44413,
  'flags': 0,
  'frag': 0,
  'ttl': 255,
  'proto': 17,
  'chksum': 37231,
  'src': '10.207.143.142',
  'dst': '224.0.0.251',
  'options': []},
 'UDP': {'sport': 5353, 'dport': 5353, 'len': 403, 'chksum': 38762},
 'DNS': {'id': 0,
  'qr': 1,
  'opcode': 0,
  'aa': 1,
  'tc': 0,
  'rd': 0,
  'ra': 0,
  'z': 0,
  'ad': 0,
  'cd': 0,
  'rcode': 0,
  'qdcount': 0,
  'ancount': 2,
  'nscount': 0,
  'arcount': 7,
  }}
# 应用程序
app = QApplication([])
window = DictTree(nested_dict)
window.show()
app.exec_()
