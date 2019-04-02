#-------------------------------------------------------------------------------
# Name:        pyWOL
# Purpose:     wake up system by sending a magic packet
#
# Author:      hansel@163.com
#
# Created:     22/03/2019
# Copyright:   (c) Hansel 2019
# Licence:     MIT license
#-------------------------------------------------------------------------------
import sys
from optparse import OptionParser
import socket
import time
import signal

BROADCAST_ADDR = '<broadcast>'
UDP_PORT = 9
count = 0

def define_cmd_line():
    usage = "usage: %prog [options] MAC"
    parser = OptionParser(usage)
    parser.add_option("-m", "--mac", dest="mac",
                      help="destination MAC address in format of xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx")
    parser.add_option("-n", "--num", type="int", dest="num", default=1
        , help="number of WOL packets to send, default is 1")
    parser.add_option("-t", "", action="store_true", default=False, dest="always"
        , help="sent WOL packets until stopped")
    parser.add_option("-a", "--address", dest="ip", default=BROADCAST_ADDR, help="Destination IP address, default is 255.255.255.255")
    parser.add_option("-p", "--port", type=int, dest="port", default=UDP_PORT, help="Destination UDP port, default is 9")
    return parser

def convert_mac_address(mac):
    mac = mac.replace("-", ":")
    mac_str = mac.split(":")
    if len(mac_str) < 6:
        raise ValueError('incorrect MAC address format')

    mac_array = [int(x, 16) for x in mac_str]
    return mac_array

def build_magic_packet(mac_array):
    mac_data = "".join(["%02X"%x for x in mac_array])
    data_str = 'FF'*6 + mac_data*16
    return bytes().fromhex(data_str)

def send_wol_packet(data, ip, port):
    num = 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        num = s.sendto(data, (ip, port))
    finally:
        s.close()
    return num

def terminal(signum, frame):
    print("\nTotal sent %d packets." % (count))
    sys.exit(0)

def main():
    global count
    if len(sys.argv) < 2:
        print("no MAC address")
        sys.exit(-1)

    parser = define_cmd_line()
    (options, args) = parser.parse_args()
    mac = options.mac if options.mac else args[0]
    ip = options.ip if options.ip else BROADCAST_ADDR
    port = options.port if options.port else UDP_PORT

    try:
        mac_array = convert_mac_address(mac)
        data = build_magic_packet(mac_array)
        mac_str = ":".join(["%02X" % x for x in mac_array])
        signal.signal(signal.SIGINT, terminal)
        while count < options.num or options.always:
            num = send_wol_packet(data, ip, port)
            print("#%d: sent %d bytes WOL packet to ip=%s:%d for MAC=%s"
                % (count, num, ip, port, mac_str))
            count = count + 1
            time.sleep(1)
    except ValueError as e:
        print("Error: " + e.args[0])
        sys.exit(-2)

    print("\nTotal sent %d packets." % (count))
if __name__ == '__main__':
    main()


