from scapy.all import *
from scapy.layers.inet import *

# #hping3 -1 --flood --spoof <target> <broadcast_address>

# src = 192.168.0.175 # target machine
# dst = 192.168.0.112

# print("Hello World")
# ip = IP(dst="192.168.0.107")
# print(ip.dst)

# print(ip.show())

# ip = ip/TCP()

# print(ip.show())

# ip.send()
for i in range(0, 1):
    send(IP(src="192.168.0.195", dst="192.168.0.175")/ICMP()/"Hello World")
    # a = sniff(filter="icmp and src 192.168.0.112")
    # a.nsummary()
