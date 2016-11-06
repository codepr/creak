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

from socket import socket, inet_aton, inet_ntoa, PF_PACKET, SOCK_RAW
from threading import Thread, Timer
import sys
import pcap
import dpkt
from baseplugin import BasePlugin
import creak.utils as utils

class Plugin(BasePlugin):

    """
    """

    def init_plugin(self):
        self._set_info(
            author='codep',
            version='1.0',
            description='Scan the local address range and records responses')
        self._set_required_params(dev=True, gateway=True, localip=True,
                                  mac_addr=True, gateway_addr=True,
                                  attempts=False, timeout=False, target=False)
        self._set_root(True)

    def run(self, kwargs):
        pcap_filter = 'arp and dst host %s' % kwargs['localip']
        packets = pcap.pcap(name=kwargs['dev'], promisc=True)
        packets.setfilter(pcap_filter)
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((kwargs['dev'], dpkt.ethernet.ETH_TYPE_ARP))
        attempts = 3
        timeout = 30

        if 'timeout' in kwargs:
            timeout = kwargs['timeout']

        if 'attempts' in kwargs:
            attempts = kwargs['attempts']

        if not 'target' in kwargs:
            kwargs['target'] = kwargs['localip']

        subnet = kwargs['target'].split('.')[:-1]
        subnet = '.'.join(subnet)
        target = subnet
        counter = 0

        print('')
        self.print_output('Waiting for responses, enter \'q\' to stop')
        self.print_output('Alive hosts:')
        print(' ====================\n')
        for _ in xrange(attempts):
            for idx in xrange(1, 255):
                arp = dpkt.arp.ARP()
                packet = dpkt.ethernet.Ethernet()
                arp.sha = utils.string_to_binary(utils.parse_mac(kwargs['mac_addr']))
                arp.spa = inet_aton(kwargs['localip'])
                arp.tha = '\x00'
                arp.tpa = inet_aton(target + '.%s' % idx)
                arp.op = dpkt.arp.ARP_OP_REQUEST
                packet.src = utils.string_to_binary(utils.parse_mac(kwargs['mac_addr']))
                packet.dst = '\xff' * 6 # broadcast address
                packet.data = arp
                packet.type = dpkt.ethernet.ETH_TYPE_ARP
                sock.send(str(packet))

        def wait_responses(packets):
            hosts = []
            for _, pkt in packets:
                eth = dpkt.ethernet.Ethernet(pkt)
                ip_packet = eth.data
                str_src_phy = utils.binary_to_string(eth.src)
                step = 2
                src_phy = [str_src_phy[i:i+step] for i in range(0,
                                                             len(str_src_phy),
                                                             step)]
                src_phy = ':'.join(src_phy)
                if src_phy not in hosts and src_phy != kwargs['mac_addr'] and src_phy != kwargs['gateway_addr']:
                    hosts.append(src_phy)
                    print(' {} - {}'.format(src_phy, inet_ntoa(ip_packet.spa)))

        wait_thread = Thread(target=wait_responses, args=(packets,))
        wait_thread.daemon = True
        wait_thread.start()

        def close():
            print('')
            self.print_output('Timer exceeded..press Enter')
            return

        t = Timer(timeout, close)
        t.start()
        comm = raw_input()
        if comm == 'q':
            t.cancel()
            return
