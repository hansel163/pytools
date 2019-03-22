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

def define_cmd_line():
    usage = "usage: %prog [options] MAC"
    parser = OptionParser(usage)
    parser.add_option("-m", "--mac", dest="mac",
                      help="destination MAC address in format of xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx")
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

def send_wol_packet(data):
    num = 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        num = s.sendto(data, ('<broadcast>', 9))
    finally:
        s.close()
    return num

def main():
    if len(sys.argv) < 2:
        print("no MAC address")
        exit(-1)

    parser = define_cmd_line()
    (options, args) = parser.parse_args()
    if options.mac:
        mac = options.mac
    else:
        mac = sys.argv[1]

    try:
        mac_array = convert_mac_address(mac)
        data = build_magic_packet(mac_array)
        num = send_wol_packet(data)
    except ValueError as e:
        print("Error: " + e.args[0])
        exit(-2)

    mac_str = ":".join(["%02X"%x for x in mac_array])
    print("Sent %d bytes to MAC: %s" % (num, mac_str))
if __name__ == '__main__':
    main()


