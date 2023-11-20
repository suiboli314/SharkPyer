'''
Project: IP Mask
Team 4 Members: Dongxin Zhang, Chenjie Wu, Mingfu Huang, Junhao Hao
'''

import pyshark
import psutil
import socket
import requests


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

# # 设置捕获过滤器（可选）
# capture.set_debug()

count = 0
# 开始捕获数据包
for packet in capture.sniff_continuously():
    if 'UDP' in packet and 'a3' in packet['UDP'].payload and packet['IP'].src == local_ip:
        # print(packet['IP'].dst)
        dst = packet['IP'].dst
        break

# 构建查询URL
url = f"http://ip-api.com/json/{dst}"

# 发送GET请求获取位置信息
response = requests.get(url)

if response.status_code == 200:
    data = response.json()
    if data["status"] == "success":
        print("IP 地址:", data["query"])
        print("位置:", data["city"])
        print("地区:", data["regionName"])
        print("国家:", data["country"])
        print("经纬度:", f"{data['lat']}, {data['lon']}")
    else:
        print("无法获取位置信息")
else:
    print("无法连接到IP地址定位服务")


# 选择接口
# def get_network_interfaces():
#     network_interfaces = psutil.net_if_addrs()
#     return list(network_interfaces.keys())
#
# if __name__ == "__main__":
#     interfaces = get_network_interfaces()
#     if not interfaces:
#         print("没有找到可选择的网络接口。")
#     else:
#         print("可选择的网络接口列表：")
#         for interface in interfaces:
#             print(interface)
