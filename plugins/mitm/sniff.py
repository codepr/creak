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

import pcap
import dpkt
from socket import inet_ntoa
from struct import unpack
from baseplugin import BasePlugin
import creak.utils as utils

class Plugin(BasePlugin):

    def init_plugin(self):
        self._set_info(
            author='codep',
            version='1.0',
            description='Poison the ARP cache of the target(s)')
        self._set_required_params(dev=True, pcap_filter=False)
        self._set_root(True)

    def run(self, kwargs):

        def decode_flag(tcp):
            return {
                'fin': (tcp.flags & dpkt.tcp.TH_FIN) != 0,
                'syn': (tcp.flags & dpkt.tcp.TH_SYN) != 0,
                'rst': (tcp.flags & dpkt.tcp.TH_RST) != 0,
                'psh': (tcp.flags & dpkt.tcp.TH_PUSH) != 0,
                'ack': (tcp.flags & dpkt.tcp.TH_ACK) != 0,
                'urg': (tcp.flags & dpkt.tcp.TH_URG) != 0,
                'ece': (tcp.flags & dpkt.tcp.TH_ECE) != 0,
                'cwr': (tcp.flags & dpkt.tcp.TH_CWR) != 0
            }

        def print_packet(ipv, L1, L2):
            print(' [{}] Header len: {} TTL: {} s_addr:'
                  ' {:<15} {:<3} {:<15} {:<3} {:<6}'
                  ' {:<3} {:<5}'.format(ipv, L1.hl, L1.ttl,
                                        inet_ntoa(L1.src),
                                        'd_addr:',
                                        inet_ntoa(L1.dst),
                                        's_port:',
                                        str(L2.sport),
                                        'd_port:',
                                        str(L2.dport)))

        packets = pcap.pcap(name=kwargs['dev'], promisc=True)
        if 'pcap_filter' in kwargs:
            packets.setfilter(kwargs['pcap_filter'])

        # can be refactored and optimized
        for _, pkt in packets:
            L0 = dpkt.ethernet.Ethernet(pkt)
            L1 = L0.data
            L2 = L1.data
            if L0.type == dpkt.ethernet.ETH_TYPE_ARP:
                op_flag = 'request'
                if L1.op == 2:
                    op_flag = 'reply'

                print(' [ARP] op: {:<8} s_h_addr: {:<8} d_h_addr: {:<8}'
                      ' s_p_addr: {:<8} d_p_addr: {:<8}'.format(op_flag,
                                                               utils.binary_to_string(L1.sha),
                                                               utils.binary_to_string(L1.tha),
                                                               inet_ntoa(L1.spa),
                                                               inet_ntoa(L1.tpa)))
            elif L0.type == dpkt.ethernet.ETH_TYPE_IP:
                ipv = 'IPv4'
                # IPv4 - TCP packet
                if L1.p == dpkt.ip.IP_PROTO_TCP:
                    tcp_flags = decode_flag(L2)
                    print_packet(ipv, L1, L2)
                    flags = [x for x in tcp_flags if tcp_flags[x]]
                    flags = ', '.join(flags)
                    print('\tFlags: {}'.format(flags))

                # IPv4 - UDP packet
                elif L1.p == dpkt.ip.IP_PROTO_UDP:
                    print_packet(ipv, L1, L2)

            elif L0.type == dpkt.ethernet.ETH_TYPE_IP6:
                ipv = 'IPv6'
                # IPv6 - TCP packet
                if L1.p == dpkt.ip.IP_PROTO_TCP:
                    tcp_flags = decode_flag(L2)
                    print_packet(ipv, L1, L2)
                    flags = [x for x in tcp_flags if tcp_flags[x]]
                    flags = ', '.join(flags)
                    print('\tFlags: {}'.format(flags))


                # IPv6 - UDP packet
                elif L1.p == dpkt.ip.IP_PROTO_UDP:
                    print_packet(ipv, L1, L2)

