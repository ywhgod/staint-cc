from scapy.all import (
    IP,
    UDP,
    Ether,
    FieldLenField,
    IntField,
    IPOption,
    Packet,
    PacketListField,
    ShortField,
    get_if_hwaddr,
    get_if_list,
    sendp
)
from scapy.all import *
import socket
import struct
import sys
from scapy.layers.inet import _IPOption_HDR

# 获取本机IP地址
def get_local_ip():
    return socket.gethostbyname(socket.gethostname())

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                    IntField("qdepth", 0)]
    def extract_padding(self, p):
        return "", p

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B", length_of="swtraces", adjust=lambda pkt,l:l*2+4),
                    ShortField("count", 0),
                    PacketListField("swtraces", [], SwitchTrace, count_from=lambda pkt:(pkt.count*1))]

# 定义处理数据包的回调函数
def handle_packet(packet):
    try:
        # 获取本机IP地址
        local_ip = "10.0.1.1"
        if packet.haslayer(IP):
            # 如果数据包是从本机发送出去的（源IP为本机IP）
            if packet[IP].src == local_ip:
                # 如果是UDP并且包含XQUIC流数据包
                if packet.haslayer(UDP):
                    # 假设XQUIC使用UDP 443端口，您可以根据实际情况修改
                    if packet[UDP].dport == 8443 or packet[UDP].sport == 8443:
                        print("XQUIC Stream Packet Detected")
                        
                        # 打印当前的IP选项
                        print(f"Current IP options: {packet[IP].options}")

                        # 创建一个新的IPOption_MRI实例
                        ip_option = IPOption_MRI(count=0, swtraces=[])  # 假设swtraces为空

                        # 重新构建IP层，并添加IP选项
                        ip_layer = IP(src=packet[IP].src, dst=packet[IP].dst, options=[ip_option])

                        # 使用新的IP层构造数据包
                        modified_packet = ip_layer/packet[IP].payload  # 重新构建数据包

                        # 打印修改后的数据包
                        print(f"Modified Packet with New IP Options: {modified_packet.summary()}")
                        print(f"Modified IP options: {modified_packet[IP].options}")

                        # 重新发送修改后的数据包
                        send(modified_packet)

    except Exception as e:
        # 捕获异常并打印错误信息
        print(f"Error processing packet: {e}")

# 设置网口并启动嗅探
def start_sniffing(interface="eth0"):
    sniff(iface=interface, prn=handle_packet, store=0)

# 启动网络嗅探
if __name__ == "__main__":
    start_sniffing("eth0")  # 可以根据需要更改网口名称