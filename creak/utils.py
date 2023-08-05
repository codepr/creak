# -*- coding: utf-8 -*-
# Copyright (c) 2014-2017 Andrea Baldan
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

""" Utility functions module """

import os
import re
import sys
import uuid
import time
import binascii
import random
import subprocess
import struct
import fcntl

try:
    xrange
except NameError:
    xrange = range

IS_PY2 = sys.version_info < (3, 0)

if IS_PY2:
    import urllib2
else:
    import urllib.request

try:
    import dpkt
except ImportError:
    print("[!] Missing module dpkt")

try:
    import ConfigParser
except ImportError:
    print("[!] Missing module ConfigParser")

from socket import socket, inet_aton, inet_ntoa, AF_INET, SOCK_DGRAM
from scapy.all import ARP, Ether, srp
# from configparser import ConfigParser

CONF = ConfigParser.ConfigParser()
CONF.read(r'creak/config')

# console colors
W = '\033[0m'  # white (normal)
R = '\033[31m' # red
G = '\033[32m' # green

def print_counter(counter):
    """ print counter in place """
    sys.stdout.write("[+] Packets [ %d ]\r" % counter)
    sys.stdout.flush()

def print_in_line(string):
    """ print without carriage return """
    sys.stdout.write(string)
    sys.stdout.flush()

def string_to_binary(string):
    """ convert string to binary format """
    return binascii.unhexlify(string)

def binary_to_string(binary):
    """ convert binary to string """
    return binascii.hexlify(binary)

def set_ip_forward(fwd):
    """ set ip_forward to fwd (0 or 1) """
    CONF.read(r'./config')
    if fwd != 1 and fwd != 0:
        raise ValueError('[.] Value not valid for ip_forward, must be either 0 or 1')
    else:
        with open(CONF.get('services', 'IP_FORWARD'), 'w') as ip_f:
            ip_f.write(str(fwd) + '\n')

def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as f_h:
        for line in f_h:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def get_mac_by_dev(dev):
    """ try to retrieve MAC address associated with device """
    try:
        sock_fd = socket(AF_INET, SOCK_DGRAM)
        info = fcntl.ioctl(sock_fd.fileno(), 0x8927, struct.pack('256s', bytes(dev[:15], 'utf-8')))
        return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    except (IOError, TypeError):
        sock_fd.close()
        mac_addr = hex(uuid.getnode()).replace('0x', '')
    return ':'.join(mac_addr[i : i + 2] for i in range(0, 11, 2))

def get_mac_by_ip(ip_addr):
    """ try to retrieve MAC address associated with ip """
    try:
        subprocess.Popen(["ping", "-c 1", ip_addr], stdout=subprocess.PIPE)
        time.sleep(0.5)
        with open("/proc/net/arp") as f_h:
            for line in f_h:
                fields = line.strip().split()
                addr = [x for x in fields if re.match(r'^(\w+:){5}\w+$', x)]
                if addr:
                    return addr[0]
    except OSError:
        pass
    try:
        subprocess.Popen(["ping", "-c 1", ip_addr], stdout=subprocess.PIPE)
        time.sleep(0.5) # just to be sure of the ping response time
        pid = subprocess.Popen(["arp", "-n", ip_addr], stdout=subprocess.PIPE)
        arp_output = pid.communicate()[0]
    except OSError:
        pass
    try:
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", arp_output).groups()[0]
    except (IndexError, UnboundLocalError):
        exit()
    return parse_mac(mac)

def get_mac_by_ip_s(ip_address, delay):
    """try to retrieve MAC address associated with ip using Scapy library """
    responses, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),
                       timeout=delay, retry=10)
    # return the MAC address from a response
    for _, response in responses:
        return response[Ether].src
    return None

def parse_mac(address):
    """ remove colon inside mac addres, if there's any """
    return address.replace(':', '')

def mac_to_hex(mac):
    """ convert string mac octets into base 16 int """
    return [int(x, 16) for x in mac.split(':')]

def fake_mac_address(prefix, mode=None):
    """ generate a fake MAC address """
    if mode == 1:
        prefix = [0x00, 0x16, 0x3e]
        prefix += [(random.randint(0x00, 0x7f)) for _ in xrange(3)]
    else:
        prefix += [(random.randint(0x00, 0xff)) for _ in xrange(6 - len(prefix))]
    return ':'.join('%02x' % x for x in prefix)

def change_mac(dev, new_mac):
    """ try to change the MAC address associated to the device """
    if os.path.exists("/usr/bin/ip") or os.path.exists("/bin/ip"):
        # turn off device
        subprocess.check_call("ip", "link", "set", "%s" % dev, "down")
        # set mac
        subprocess.check_call("ip", "link", "set", "%s" % dev, "address", "%s" % new_mac)
        # turn on device
        subprocess.check_call("ip", "link", "set", "%s" % dev, "up")
    else:
        # turn off device
        subprocess.check_call(["ifconfig", "%s" % dev, "down"])
        # set mac
        subprocess.check_call(["ifconfig", "%s" % dev, "hw", "ether", "%s" % new_mac])
        # turn on device
        subprocess.check_call(["ifconfig", "%s" % dev, "up"])
        # restart network
        if CONF.get('restart', 'NETWORK_RESTART').startswith('systemctl'):
            subprocess.check_call([CONF.get('restart', 'NETWORK_RESTART')])
        else:
            subprocess.check_call([CONF.get('restart', 'NETWORK_RESTART'), "restart"])

def eth_ntoa(buf):
    """ convert a MAC address from binary packed bytes to string format """
    mac_addr = ''
    for intval in struct.unpack('BBBBBB', buf):
        mac_addr = ''.join([mac_addr, hex(intval).replace('0x' if intval > 15 else 'x', '')])

    return mac_addr

def eth_aton(buf):
    """ convert a MAC address from string to binary packed bytes format """
    addr = ''
    for i in xrange(0, len(buf), 2):
        addr = ''.join([addr, struct.pack('B', int(buf[i: i + 2], 16))],)
    return addr

def build_arp_packet(source_mac, src, dst):
    """ forge arp packets used to poison and reset target connection """
    arp = dpkt.arp.ARP()
    packet = dpkt.ethernet.Ethernet()
    arp.sha = string_to_binary(source_mac)
    arp.spa = inet_aton(dst)
    arp.tha = '\x00' * 6
    arp.tpa = inet_aton(src)
    arp.op = dpkt.arp.ARP_OP_REPLY
    packet.src = string_to_binary(source_mac)
    packet.dst = '\xff' * 6 # broadcast address
    packet.data = arp
    packet.type = dpkt.ethernet.ETH_TYPE_ARP
    return packet

def get_manufacturer(manufacturer):
    """
    get a list of MAC octets based on manufacturer fetching data from
    http://anonsvn.wireshark.org/wireshark/trunk/manuf
    """
    output, m_list = [], None
    url_lib = urllib2 if IS_PY2 else urllib.request

    if not os.path.exists("./manufacturers"):
        os.makedirs("./manufacturers")

    if not os.path.isfile("./manufacturers/list.txt"):
        print("[+] No local cache data found for " + G + manufacturer + W
              + " found, fetching from web..")
        urls = url_lib.urlopen(CONF.get('services', 'MANUFACTURER_URL'))
        macs = _manufacturers(manufacturer, urls)
    else:
        print("[+] Fetching data from local cache..")
        conf = ConfigParser.ConfigParser()
        conf.read("./manufacturers/list.txt")

        macs = conf.get(manufacturer.lower(), 'MAC').split(',')
        if len(macs) > 0:
            print("[+] Found mac octets from local cache for " + G + manufacturer + W
                  + " device")
            return macs
        else:
            urls = url_lib.urlopen(CONF.get('services', 'MANUFACTURER_URL'))
            macs = _manufacturers(manufacturer, urls)

    with open("./manufacturers/list.txt", "wa+") as m_list:
        m_list.write("[" + manufacturer.lower() + "]\nMAC = ")
        m_list.write(",".join(macs))
        m_list.write("\n")

    return macs

def _manufacturers(manufacturer, urls):
    [_get_mac(manufacturer, line) for line in urls]

def _get_mac(manufacturer, line):
    addr = line.split()
    if len(addr) < 1:
        continue
    mac, man = addr
    if re.search(manufacturer.lower(), man.lower()) and 1 < len(mac) < 17:
        # python2.x ignore byte string b''
        return (mac if IS_PY2 else mac.decode('utf-8'))

def is_ipv4(ipstring):
    """ check if the given string is an ipv4"""
    match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ipstring)
    return bool(match) and all(map(lambda n: 0 <= int(n) <= 255, match.groups()))
