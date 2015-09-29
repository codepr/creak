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

import os
import re
import sys
import binascii
import random
import subprocess
import struct
import fcntl
import dpkt
import urllib2
import ConfigParser
import config
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

def set_ip_forward(fwd):
	""" set ip_forward to fwd (0 or 1) """
	if fwd != 1 and fwd != 0:
		raise ValueError('[.] Value not valid for ip_forward, must be either 0 or 1')
	else:
		with open(config.ip_forward, 'w') as ip_f:
			ip_f.write(str(fwd) + '\n')

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
	return address.replace(':', '')

def mac_to_hex(mac):
	""" convert string mac octets into base 16 int """
	return [int(x, 16) for x in mac.split(':')]

def fake_mac_address(prefix = [], mode = None):
	""" generate a fake MAC address """
	if mode == 1:
		prefix = [0x00, 0x16, 0x3e]
		prefix += [(random.randint(0x00, 0x7f)) for p in xrange(3)]
	else:
		prefix += [(random.randint(0x00, 0xff)) for p in xrange(6 - len(prefix))]
	return ':'.join('%02x' % x for x in prefix)

def change_mac(dev, new_mac):
	""" try to change the MAC address associated to the device """
	subprocess.check_call(["ifconfig", "%s" % dev, "down"])
	subprocess.check_call(["ifconfig", "%s" % dev, "hw", "ether", "%s" % new_mac])
	subprocess.check_call(["ifconfig", "%s" % dev, "up"])
	subprocess.check_call([config.NETWORK_RESTART, "restart"])

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

def get_manufacturer(manufacturer):
	"""
	get a list of MAC octets based on manufacturer fetching data from
	http://anonsvn.wireshark.org/wireshark/trunk/manuf
	"""
	output = []
	m_list = None
	if not os.path.exists("./manufacturers"):
		os.makedirs("./manufacturers")
	if not os.path.isfile("./manufacturers/list.txt"):
		print "[+] No local cache data found for " + G + manufacturer + W + " found, fetching from web.."
		try:
			u = urllib2.urlopen(config.MANUFACTURER_URL)
			m_list = open("./manufacturers/list.txt", "w+r")
			for line in u:
				try:
					mac = line.split()[0]
					man = line.split()[1]
					if re.search(manufacturer.lower(), man.lower()) and len(mac) < 17 and len(mac) > 1:
						output.append(mac)
				except IndexError:
					pass
			if len(output) > 0:
				m_list.write("[" + manufacturer.lower() + "]\nMAC = ")
				m_list.write(",".join(output))
				m_list.write("\n")
		except:
			print "[!] Error occured while trying to fetch data for manufacturer based mac address"
			pass
	else:
		macs = []
		print "[+] Fetching data from local cache.."
		conf = ConfigParser.ConfigParser()
		conf.read("./manufacturers/list.txt")
		try:
			macs = conf.get(manufacturer.lower(), 'MAC').split(',')
			if len(macs) > 0:
				print "[+] Found mac octets from local cache for " + G + manufacturer + W + " device"
				return macs
		except:
			u = urllib2.urlopen(config.MANUFACTURER_URL)
			m_list = open("./manufacturers/list.txt", "a+r")
			for line in u:
				try:
					mac = line.split()[0]
					man = line.split()[1]
					if re.search(manufacturer.lower(), man.lower()) and len(mac) < 17 and len(mac) > 1:
						output.append(mac)
				except IndexError:
					pass
			if len(output):
				m_list.write("[" + manufacturer.lower() + "]\nMAC = ")
				m_list.write(",".join(output))
				m_list.write("\n")
	m_list.close()
	return output
