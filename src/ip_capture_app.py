'''
Project: IP Mask
Team 4 Members: Dongxin Zhang, Chenjie Wu, Mingfu Huang, Junhao Hao
'''

# Import necessary PyQt6 modules
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QColor, QPixmap
from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QCheckBox, QPushButton, QStackedWidget, \
    QLabel, QTableWidget, QTableWidgetItem, QSizePolicy, QHeaderView, QComboBox, QFrame

# Other required libraries
import pyshark
import psutil
import requests
from scapy.all import *
from scapy.layers.inet6 import *


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
        self.setWindowTitle("IP Mask")
        self.setGeometry(100, 100, 600, 400)  # Set initial size
        self.setWindowIcon(QIcon('path_to_icon.png'))  # Set window icon
        # Create a stacked widget to manage pages

        # Styling
        # self.setStyleSheet("""
        #     QMainWindow {
        #         background-color: #ffffff;
        #     }
        #     QLabel, QComboBox, QPushButton {
        #         font-size: 14px;
        #         color: #000103;
        #     }
        #     QPushButton {
        #         background-color: #62baf5;
        #         border-radius: 5px;
        #         padding: 5px;
        #         color: #ffffff;
        #         font-weight: bold;
        #     }
        #     QPushButton:hover {
        #         background-color: #2980b9;
        #     }
        #     QTableWidget {
        #         gridline-color: #7f8c8d;
        #     }
        #     QHeaderView::section {
        #         background-color: #62baf5;
        #         padding: 4px;
        #         border: 1px solid #7f8c8d;
        #         font-size: 14px;
        #         color: #ffffff;
        #         font-weight: bold;
        #     }
        # """)

        # 使用更现代的字体和配色方案
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f2f2f2; 
            }
            QLabel, QComboBox, QPushButton {
                font-family: 'Arial', sans-serif; 
                font-size: 14px;
                color: #333333;
            }
            QPushButton {
                background-color: #4285f4; 
                border-radius: 4px; 
                padding: 10px;
                color: #ffffff; 
                font-weight: bold; 
            }
            QPushButton:hover {
                background-color: #357ae8; 
            }
            QTableWidget {
                border: none; 
                selection-background-color: #4285f4; 
            }
            QHeaderView::section {
                background-color: #4285f4; 
                padding: 5px;
                border: 1px solid #e0e0e0; 
                font-size: 14px;
                color: #ffffff; 
                font-weight: bold; 
            }
            QComboBox {
                border: 1px solid #e0e0e0; 
                border-radius: 4px; 
            }
            QComboBox:hover {
                border-color: #4285f4; 
            }
            QComboBox::drop-down {
                border: none; 
            }
            QTableWidget {
                selection-background-color: #4285f4;
                selection-color: #ffffff;
            }
        """)

        # Main layout
        layout = QVBoxLayout()
        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        # Network Interface Selection
        label = QLabel('Select network interface:')
        # label.setAlignment(Qt.AlignCenter)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.combo_box = QComboBox()
        self.combo_box.addItems(self.get_network_interfaces())

        self.confirm_button = QPushButton('Confirm')
        self.confirm_button.clicked.connect(self.display_selected_interface)

        layout.addWidget(label)
        layout.addWidget(self.combo_box)
        layout.addWidget(self.confirm_button)

        # Information Display
        self.info_label = QLabel('Selected interface will be displayed here')
        self.info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(2)
        self.table_widget.setHorizontalHeaderLabels(['Content', 'Result'])
        # self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.info_label)
        layout.addWidget(self.table_widget)

        # confirm_button.setStyleSheet("background-color: #34a853;")  # 绿色按钮表示确认动作
        self.confirm_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50; 
                color: white; 
                border-radius: 4px; 
                padding: 5px; 
                border: none; 
            }
            QPushButton:hover {
                background-color: #45A049; 
            }
            QPushButton:pressed {
                background-color: #397D39; 
            }
        """)

        # self.stacked_widget = QStackedWidget(self)

        # # Create the first page (select network interface)
        # page1 = QWidget()
        # layout1 = QVBoxLayout(page1)
        # layout1.setContentsMargins(5, 5, 5, 5)  # Set layout margins
        # layout1.setSpacing(0)  # Set layout spacing
        #
        # # Add a label for selecting network interfaces
        # label = QLabel("Select network interface:", self)
        # label.setStyleSheet("QComboBox { border: 2px solid blue; }")
        #
        # # label.setAlignment(Qt.AlignCenter)  # 设置标签文本居中对齐
        # # label.setFont(QFont('Arial', 10))  # 设置标签的字体和字体大小
        # # label.setMargin(5)  # 设置标签的边距，可以根据需要调整
        # layout1.addWidget(label)
        #
        # # Obtain a list of network interfaces and create a dropdown menu
        # network_interfaces = self.get_network_interfaces()
        # self.combo_box = QComboBox(self)
        # self.combo_box.addItems(network_interfaces)
        # layout1.addWidget(self.combo_box)
        #
        # # Add a confirm button
        # confirm_button = QPushButton("Confirm", self)
        # confirm_button.clicked.connect(self.next_page)
        # layout1.addWidget(confirm_button)
        #
        # # Configure layout and add to the stacked widget
        # page1.setLayout(layout1)
        # self.stacked_widget.addWidget(page1)
        #
        # # Create the second page (display selected results)
        # page2 = QWidget()
        # layout2 = QVBoxLayout()
        # # layout2.setContentsMargins(0, 0, 0, 0)  #
        # # layout2.setSpacing(0)
        # self.selection_label = QLabel("The Network Interface You Selected", self)
        # layout2.addWidget(self.selection_label)
        # page2.setLayout(layout2)
        # self.stacked_widget.addWidget(page2)
        #
        # # self.info_label = QLabel("", self)
        # # layout2.addWidget(self.info_label)
        #
        # # Create a table widget for displaying information
        # self.table_widget = QTableWidget(self)
        # self.table_widget.setColumnCount(2)  # 设置表格列数
        #
        # # Configure table properties
        #
        # self.table_widget.setFrameStyle(QFrame.Shape.NoFrame)
        # self.table_widget.setContentsMargins(0, 0, 0, 0)
        # sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        # sizePolicy.setHorizontalStretch(1)
        # sizePolicy.setVerticalStretch(0)
        # self.table_widget.setSizePolicy(sizePolicy)
        # self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)  # 设置列自适应宽度
        # self.table_widget.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)  # 设置行高自适应内容
        #
        # layout2.addWidget(self.table_widget)
        #
        # # Add a button to initiate background task
        # get_info_button = QPushButton("Get Information", self)
        # get_info_button.clicked.connect(self.start_background_task)
        # layout2.addWidget(get_info_button)
        #
        # # Set the current page in the stacked widget
        # self.stacked_widget.setCurrentIndex(0)
        #
        # # Set the main window layout
        # layout = QVBoxLayout()
        # layout.setContentsMargins(0, 0, 0, 0)
        # layout.setSpacing(0)
        # layout.addWidget(self.stacked_widget)
        # central_widget = QWidget(parent=None)
        # central_widget.setLayout(layout)
        # self.setCentralWidget(central_widget)

    # Function to get a list of network interfaces using psutil
    def get_network_interfaces(self):
        network_interfaces = psutil.net_if_addrs()
        return list(network_interfaces.keys())

    def display_selected_interface(self):

        self.confirm_button.setStyleSheet("background-color: #FF0000; color: white;")
        self.confirm_button.setText("CONFIRMED")
        self.combo_box.setEnabled(False)
        self.combo_box.setStyleSheet("""
                    QComboBox {
                        background-color: #e0e0e0; /* 浅灰色背景 */
                        color: #a0a0a0; /* 淡灰色文字 */
                    }
                    QComboBox::drop-down {
                        background: transparent;
                    }
                    QComboBox::down-arrow {
                        image: none;
                    }
                """)


        selected_interface = self.combo_box.currentText()
        self.info_label.setText(f'Current Interface: {selected_interface}')
        # self.get_information()
        self.start_background_task()

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
    def print_info(self, response, App):
        # Handle different response scenarios
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                # Prepare information data
                info_data = [
                    ("App", App),
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
                self.table_widget.setHorizontalHeaderLabels(['Content', 'Result'])
                self.table_widget.setFrameShape(QFrame.Shape.NoFrame)
                self.table_widget.setContentsMargins(0, 0, 0, 0)

                for row, (key, value) in enumerate(info_data):
                    key_item = QTableWidgetItem(key)
                    value_item = QTableWidgetItem(value)
                    self.table_widget.setItem(row, 0, key_item)
                    self.table_widget.setItem(row, 1, value_item)

                # self.table_widget.resizeColumnsToContents()
                # self.table_widget.resizeRowsToContents()

                # Display error message in table
                for row, (key, value) in enumerate(info_data):
                    key_item = QTableWidgetItem(key)
                    value_item = QTableWidgetItem(value)
                    self.table_widget.setItem(row, 0, key_item)
                    self.table_widget.setItem(row, 1, value_item)
            # else:
                # Display error message in table
                # self.table_widget.clear()
                # self.table_widget.setRowCount(1)
                # self.table_widget.setItem(0, 0, QTableWidgetItem("Unable to fetch location information"))
        else:
            # Display error message in table
            self.table_widget.clear()
            self.table_widget.setRowCount(1)
            self.table_widget.setItem(0, 0, QTableWidgetItem("Unable to connect to IP address location service"))


# Class for a long-running task in a separate thread
class LongRunningTask(QThread):
    update_signal = pyqtSignal(requests.models.Response, str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.local_ip = get_local_ip_address()
        self.lookup_pid = get_pid("WeChat")
        self.target_ports, self.target_ip = get_used_port_by_pid(self.lookup_pid, set(), set())

    # Run method for the thread
    def run(self):
        # live capture network flow
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        capture = pyshark.LiveCapture(interface=self.interface)

        capture.set_debug()

        count = 0
        # capture packets
        for packet in capture.sniff_continuously():
            # print(packet)
            if "UDP" in packet and "02:00:48" in packet["UDP"].payload and packet["IP"].src == self.local_ip:
                # print(packet["IP"].dst)
                dst = packet["IP"].dst
                self.lookup(dst, "QQ")
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
                            self.lookup(dst_ip, "WeChat")
                            print(dst_ip)

                            p = PacketProcessor(self.target_ports, self.target_ip)
                            sniff(filter="ip", prn=p.packet_sniffer)
                            # print(packet[packet.transport_layer])
                            # break
            except AttributeError:
                # This handles packets that might not have IP layer or other exceptions
                pass
            self.target_ports, self.target_ip = get_used_port_by_pid(self.lookup_pid, self.target_ports, self.target_ip)

    def lookup(self, ip, App):
        # URL for location 
        url = f"http://ip-api.com/json/{ip}"

        # send GET request to retrieve location
        response = requests.get(url)
        # print(response)
        self.update_signal.emit(response, App)


class PacketProcessor:
    def __init__(self, ports, ip):
        self.ports: set = ports
        self.ips: set = ip

    def modify_and_send_packet(self, packet, new_src_ip):
        # Make a copy of the original packet
        modified_packet = packet.copy()

        # Modify IPv4 packet
        if IP in modified_packet:
            modified_packet[IP].src = new_src_ip
            transport = [TCP, UDP]
            for t in transport:
                if t in modified_packet:
                    del modified_packet[IP].chksum
                    del modified_packet[t].chksum

        # Modify IPv6 packet
        elif IPv6 in modified_packet:
            modified_packet[IPv6].src = new_src_ip
            # IPv6 packets do not use header checksums like IPv4

        # Reconstruct the packet and send
        modified_packet = modified_packet.__class__(bytes(modified_packet))
        print("modified", modified_packet.summary(), "\noriginal: ", packet.summary())
        # send(modified_packet)

    def modify(self, packet):
        new_src_ip = "8.8.8.8"  # Set your new source IP
        self.modify_and_send_packet(packet, new_src_ip)

    def packet_sniffer(self, packet):

        # Example condition: TCP packet on port 80 (for both IPv4 and IPv6)
        transport = [TCP, UDP]
        for t in transport:
            if (t in packet) and (packet[t].dport in self.ports or packet[t].sport in self.ports):
                self.modify(packet)
                print("GET\t", packet[t])
        if IP in packet and packet[IP].dst in self.ips:
            self.modify(packet)
            print("GET\t", packet[IP])


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
    return addr.ip not in ips or addr.port not in ports


def fit_rule(addr, con, ports, ips):
    # print("port:", addr.port, "\tstatus:", con.status, "\tip:", addr.ip)
    port, ip = addr.port, addr.ip
    if int(port) > 4000 and port not in ports:
        ports.add(port)
        print("port:", ports, "ips:", ips)
    if not ip.startswith("10.") and not ip.startswith("0.") and ip not in ips:
        ips.add(ip)
        print("port:", ports, "ips:", ips)


def get_used_port_by_pid(pid, ports: set, ips: set):
    connections = psutil.net_connections()
    for con in connections:
        if con.pid in pid:
            if con.raddr != tuple() and new_port_ip_rule(con.raddr, ports, ips):
                fit_rule(con.raddr, con, ports, ips)
            if con.laddr != tuple() and new_port_ip_rule(con.laddr, ports, ips):
                fit_rule(con.laddr, con, ports, ips)
            if con.laddr == tuple() and con.raddr == tuple():
                print("con: ", con)

    return ports, ips


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkInterfaceApp()
    window.show()
    sys.exit(app.exec())
