import asyncio
import sys

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QCheckBox, QPushButton, QStackedWidget, \
    QLabel, QTableWidget, QTableWidgetItem, QSizePolicy, QHeaderView, QComboBox, QFrame
import pyshark
import psutil
import socket
import requests


class NetworkInterfaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.task = None
        self.init_ui()

    def applicationSupportsSecureRestorableState(self):
        return True

    def init_ui(self):
        self.setWindowTitle('Select Network Interface')
        # self.setGeometry(100, 100, 400, 200)

        # 创建堆叠窗口
        self.stacked_widget = QStackedWidget(self)

        # 创建第一页（选择网络接口）
        page1 = QWidget()
        layout1 = QVBoxLayout(page1)
        layout1.setContentsMargins(5, 5, 5, 5)  # 设置边距为0
        layout1.setSpacing(0)  # 设置间隔为0

        # 添加顶部文字标签
        label = QLabel('Select network interface:', self)
        label.setStyleSheet("QComboBox { border: 2px solid blue; }")

        # label.setAlignment(Qt.AlignCenter)  # 设置标签文本居中对齐
        # label.setFont(QFont('Arial', 10))  # 设置标签的字体和字体大小
        # label.setMargin(5)  # 设置标签的边距，可以根据需要调整
        layout1.addWidget(label)

        # 获取网络接口列表
        network_interfaces = self.get_network_interfaces()

        # 创建下拉菜单并添加到布局
        self.combo_box = QComboBox(self)
        self.combo_box.addItems(network_interfaces)
        layout1.addWidget(self.combo_box)

        # 添加确认按钮
        confirm_button = QPushButton('Confirm', self)
        confirm_button.clicked.connect(self.next_page)
        layout1.addWidget(confirm_button)

        page1.setLayout(layout1)
        self.stacked_widget.addWidget(page1)

        # 创建第二页（显示选择结果）
        page2 = QWidget()
        layout2 = QVBoxLayout()
        # layout2.setContentsMargins(0, 0, 0, 0)  # 设置边距为0
        # layout2.setSpacing(0)  # 设置间隔为0
        self.selection_label = QLabel('The Network Interface You Selected', self)
        layout2.addWidget(self.selection_label)
        page2.setLayout(layout2)
        self.stacked_widget.addWidget(page2)

        # # 创建一个 QLabel 用于显示信息
        # self.info_label = QLabel('', self)
        # layout2.addWidget(self.info_label)

        # 创建一个 QTableWidget 用于显示信息
        self.table_widget = QTableWidget(self)
        self.table_widget.setColumnCount(2)  # 设置表格列数

        # # 设置表格的外边框为 NoFrame
        self.table_widget.setFrameStyle(QFrame.Shape.NoFrame)
        # 设置表格的边距为0
        self.table_widget.setContentsMargins(0, 0, 0, 0)

        # 设置表格的大小策略
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        self.table_widget.setSizePolicy(sizePolicy)
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)  # 设置列自适应宽度
        self.table_widget.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)  # 设置行高自适应内容

        layout2.addWidget(self.table_widget)

        # 按钮
        get_info_button = QPushButton('Get Information', self)
        get_info_button.clicked.connect(self.start_background_task)
        layout2.addWidget(get_info_button)

        # 设置堆叠窗口的当前页面
        self.stacked_widget.setCurrentIndex(0)

        # 设置主窗口的布局
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)  # 设置主布局边距为0
        layout.setSpacing(0)  # 设置主布局间隔为0
        layout.addWidget(self.stacked_widget)
        central_widget = QWidget(parent=None)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def get_network_interfaces(self):
        # 使用 psutil 获取网络接口列表
        network_interfaces = psutil.net_if_addrs()
        return list(network_interfaces.keys())

    def next_page(self):
        selected_interface = self.combo_box.currentText()
        # 切换到第二页并显示选择结果
        self.selection_label.setText(f'Current Interface: {selected_interface}')
        self.stacked_widget.setCurrentIndex(1)

    async def get_information_async(self):
        # 在异步函数中执行获取信息的操作
        loop = asyncio.get_event_loop()
        info_text = await loop.run_in_executor(None, self.get_information)

        # 将信息显示在 QLabel 中
        self.info_label.setText(info_text)

    def start_background_task(self):
        if self.task is None or not self.task.isRunning():
            self.task = LongRunningTask()
            self.task.update_signal.connect(self.print_info)
            self.task.start()

    def print_info(self, response):
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                info_data = [
                    ("IP 地址", data['query']),
                    ("位置", data['city']),
                    ("地区", data['regionName']),
                    ("国家", data['country']),
                    ("经纬度", f"{data['lat']}, {data['lon']}"),
                ]

                self.table_widget.clear()
                self.table_widget.setRowCount(len(info_data))
                self.table_widget.setColumnCount(2)
                self.table_widget.setFrameShape(QTableWidget.NoFrame)
                self.table_widget.setContentsMargins(0, 0, 0, 0)

                # 将信息添加到表格中
                for row, (key, value) in enumerate(info_data):
                    key_item = QTableWidgetItem(key)
                    value_item = QTableWidgetItem(value)
                    self.table_widget.setItem(row, 0, key_item)
                    self.table_widget.setItem(row, 1, value_item)

                self.table_widget.resizeColumnsToContents()
                self.table_widget.resizeRowsToContents()

                # 将信息添加到表格中
                for row, (key, value) in enumerate(info_data):
                    key_item = QTableWidgetItem(key)
                    value_item = QTableWidgetItem(value)
                    self.table_widget.setItem(row, 0, key_item)
                    self.table_widget.setItem(row, 1, value_item)
            else:
                # 清空表格
                self.table_widget.clear()
                self.table_widget.setRowCount(1)
                self.table_widget.setItem(0, 0, QTableWidgetItem("无法获取位置信息"))
        else:
            # 清空表格
            self.table_widget.clear()
            self.table_widget.setRowCount(1)
            self.table_widget.setItem(0, 0, QTableWidgetItem("无法连接到IP地址定位服务"))


class LongRunningTask(QThread):
    update_signal = pyqtSignal(requests.models.Response)

    def run(self):
        # 获取本机的IP地址
        def get_local_ip_address():
            try:
                # 创建一个套接字连接到一个外部地址（例如 8.8.8.8）
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip_address = s.getsockname()[0]
                s.close()
                return local_ip_address
            except Exception as e:
                return str(e)

        local_ip = get_local_ip_address()

        # 监听网络接口
        capture = pyshark.LiveCapture(interface='en0')

        # 设置捕获过滤器（可选）
        capture.set_debug()

        count = 0
        # 开始捕获数据包
        for packet in capture.sniff_continuously():
            if 'UDP' in packet and '02:00:48' in packet['UDP'].payload and packet['IP'].src == local_ip:
                # print(packet['IP'].dst)
                dst = packet['IP'].dst
                break

        # 构建查询URL
        url = f"http://ip-api.com/json/{dst}"

        # 发送GET请求获取位置信息
        response = requests.get(url)
        self.update_signal.emit(response)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NetworkInterfaceApp()
    window.show()
    sys.exit(app.exec())
