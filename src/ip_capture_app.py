import asyncio
import sys

# Import necessary PyQt6 modules
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QCheckBox, QPushButton, QStackedWidget, \
    QLabel, QTableWidget, QTableWidgetItem, QSizePolicy, QHeaderView, QComboBox, QFrame

# Other required libraries
import pyshark
import psutil
import socket
import requests


# Define the main class for the Network Interface Application
class NetworkInterfaceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.task = None  # Task initialization
        self.init_ui()  # Initialize the user interface

    # Function to indicate support for secure restorable state (not used)
    def applicationSupportsSecureRestorableState(self):
        return True

    # Function to initialize the user interface
    def init_ui(self):
        self.setWindowTitle("Select Network Interface")

        # Create a stacked widget to manage pages

        self.stacked_widget = QStackedWidget(self)

        # Create the first page (select network interface)
        page1 = QWidget()
        layout1 = QVBoxLayout(page1)
        layout1.setContentsMargins(5, 5, 5, 5)  # Set layout margins
        layout1.setSpacing(0)  # Set layout spacing

        # Add a label for selecting network interfaces
        label = QLabel("Select network interface:", self)
        label.setStyleSheet("QComboBox { border: 2px solid blue; }")

        # label.setAlignment(Qt.AlignCenter)  # 设置标签文本居中对齐
        # label.setFont(QFont('Arial', 10))  # 设置标签的字体和字体大小
        # label.setMargin(5)  # 设置标签的边距，可以根据需要调整
        layout1.addWidget(label)

        # Obtain a list of network interfaces and create a dropdown menu
        network_interfaces = self.get_network_interfaces()
        self.combo_box = QComboBox(self)
        self.combo_box.addItems(network_interfaces)
        layout1.addWidget(self.combo_box)

        # Add a confirm button
        confirm_button = QPushButton("Confirm", self)
        confirm_button.clicked.connect(self.next_page)
        layout1.addWidget(confirm_button)

        # Configure layout and add to the stacked widget
        page1.setLayout(layout1)
        self.stacked_widget.addWidget(page1)

        # Create the second page (display selected results)
        page2 = QWidget()
        layout2 = QVBoxLayout()
        # layout2.setContentsMargins(0, 0, 0, 0)  # 
        # layout2.setSpacing(0)  
        self.selection_label = QLabel("The Network Interface You Selected", self)
        layout2.addWidget(self.selection_label)
        page2.setLayout(layout2)
        self.stacked_widget.addWidget(page2)

        # self.info_label = QLabel("", self)
        # layout2.addWidget(self.info_label)

        # Create a table widget for displaying information
        self.table_widget = QTableWidget(self)
        self.table_widget.setColumnCount(2)  # 设置表格列数

        # Configure table properties

        self.table_widget.setFrameStyle(QFrame.Shape.NoFrame)
        self.table_widget.setContentsMargins(0, 0, 0, 0)
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        self.table_widget.setSizePolicy(sizePolicy)
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)  # 设置列自适应宽度
        self.table_widget.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)  # 设置行高自适应内容

        layout2.addWidget(self.table_widget)

        # Add a button to initiate background task
        get_info_button = QPushButton("Get Information", self)
        get_info_button.clicked.connect(self.start_background_task)
        layout2.addWidget(get_info_button)

        # Set the current page in the stacked widget
        self.stacked_widget.setCurrentIndex(0)

        # Set the main window layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.stacked_widget)
        central_widget = QWidget(parent=None)
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    # Function to get a list of network interfaces using psutil
    def get_network_interfaces(self):
        network_interfaces = psutil.net_if_addrs()
        return list(network_interfaces.keys())

    # Function to move to the next page and display selected interface
    def next_page(self):
        selected_interface = self.combo_box.currentText()
        self.selection_label.setText(f"Current Interface: {selected_interface}")
        self.stacked_widget.setCurrentIndex(1)

    # Function to start the background task
    def start_background_task(self):
        if self.task is None or not self.task.isRunning():
            self.task = LongRunningTask(interface=self.combo_box.currentText())
            self.task.update_signal.connect(self.print_info)
            self.task.start()

    # Function to handle the response and populate the table widget
    def print_info(self, response):
        # Handle different response scenarios
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                # Prepare information data
                info_data = [
                    ("IP Address", data['query']),
                    ("Location", data['city']),
                    ("Region", data['regionName']),
                    ("Country", data['country']),
                    ("Latitude/Longitude", f"{data['lat']}, {data['lon']}"),
                ]

                # Clear and set table contents based on information data
                self.table_widget.clear()
                self.table_widget.setRowCount(len(info_data))
                self.table_widget.setColumnCount(2)
                self.table_widget.setFrameShape(QFrame.Shape.NoFrame)
                self.table_widget.setContentsMargins(0, 0, 0, 0)

                for row, (key, value) in enumerate(info_data):
                    key_item = QTableWidgetItem(key)
                    value_item = QTableWidgetItem(value)
                    self.table_widget.setItem(row, 0, key_item)
                    self.table_widget.setItem(row, 1, value_item)

                self.table_widget.resizeColumnsToContents()
                self.table_widget.resizeRowsToContents()

                # Display error message in table
                for row, (key, value) in enumerate(info_data):
                    key_item = QTableWidgetItem(key)
                    value_item = QTableWidgetItem(value)
                    self.table_widget.setItem(row, 0, key_item)
                    self.table_widget.setItem(row, 1, value_item)
            else:
                # Display error message in table
                self.table_widget.clear()
                self.table_widget.setRowCount(1)
                self.table_widget.setItem(0, 0, QTableWidgetItem("Unable to fetch location information"))
        else:
            # Display error message in table
            self.table_widget.clear()
            self.table_widget.setRowCount(1)
            self.table_widget.setItem(0, 0, QTableWidgetItem("Unable to connect to IP address location service"))


# Class for a long-running task in a separate thread
class LongRunningTask(QThread):
    update_signal = pyqtSignal(requests.models.Response)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.local_ip = get_local_ip_address()
        self.lookup_pid = get_pid("WeChat")
        self.target_ports, self.target_ip = get_used_port_by_pid(self.lookup_pid, set(), set())

    # Run method for the thread
    def run(self):
        # live capture network flow
        capture = pyshark.LiveCapture(interface=self.interface)

        capture.set_debug()

        count = 0
        # capture packets
        for packet in capture.sniff_continuously():
            # print(packet)
            if "UDP" in packet and "02:00:48" in packet["UDP"].payload and packet["IP"].src == self.local_ip:
                # print(packet["IP"].dst)
                dst = packet["IP"].dst
                self.lookup(dst)
                # break

            try:
                # Check if the packet contains IP layer
                if 'IP' in packet:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst

                    # Implement your rule here
                    if src_ip == self.local_ip:
                        # Print or process packet information
                        if int(packet[packet.transport_layer].dstport) in self.target_ports \
                                or dst_ip in self.target_ip:
                            self.lookup(dst_ip)
                            print(dst_ip)
                            # print(packet[packet.transport_layer])
                            # break
            except AttributeError:
                # This handles packets that might not have IP layer or other exceptions
                pass
            self.target_ports, self.target_ip = get_used_port_by_pid(self.lookup_pid, self.target_ports, self.target_ip)

    def lookup(self, ip):
        # URL for location 
        url = f"http://ip-api.com/json/{ip}"

        # send GET request to retrieve location
        response = requests.get(url)
        self.update_signal.emit(response)


# Function to obtain local IP address
def get_local_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip_address = s.getsockname()[0]
        s.close()
        return local_ip_address
    except Exception as e:
        return str(e)


def get_pid(process_name):
    ret = set()
    for proc in psutil.process_iter():
        if process_name in proc.name():
            ret.add(proc.pid)
    print("Pid (", process_name, "):", ret)
    return ret


def new_port_ip_rule(addr, ports, ips):
    print("ip:", addr.ip, "\t ports:", ports, "\tips:", ips)
    return addr.ip not in ips or addr.port not in ports


def get_used_port_by_pid(pid, ports: set, ips: set):
    connections = psutil.net_connections()
    for con in connections:
        if con.pid in pid:
            if con.raddr != tuple() and new_port_ip_rule(con.raddr, ports, ips):
                print("port:", con.raddr.port, "\tstatus:", con.status, "\tip:", con.raddr.ip)
                if int(con.raddr.port) > 4000:
                    ports.add(con.raddr.port)
                ips.add(con.raddr.ip)
            elif con.laddr != tuple() and new_port_ip_rule(con.laddr, ports, ips):
                print("port:", con.laddr.port, "\tstatus:", con.status, "\tip:", con.laddr.ip)
                if int(con.laddr.port) > 4000:
                    ports.add(con.laddr.port)
                ips.add(con.laddr.ip)
            else:
                print("con:", con)

    # print("port (", pid, "):", ports)
    # print("ips:", ips)

    return ports, ips


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkInterfaceApp()
    window.show()
    sys.exit(app.exec())
