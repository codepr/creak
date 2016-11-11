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
import dpkt
from creak.baseplugin import BasePlugin
import creak.utils as utils
import creak.config as config

class Plugin(BasePlugin):

    def init_plugin(self):
        self._set_info(
            author='codep',
            version='1.0',
            description='Restore to the original physical addresses a poisoned ARP cache')
        self._set_required_params(dev=True, target=True, gateway=True, src_mac=False, delay=False, stop=False)
        self._set_root(True)

    def run(self, kwargs):
        """ reset arp cache of the kwargs['target'] and the router (AP) """
        source_mac = utils.get_mac_by_ip(kwargs['gateway'])
        sock = socket(PF_PACKET, SOCK_RAW)
        sock.bind((kwargs['dev'], dpkt.ethernet.ETH_TYPE_ARP))
        if not isinstance(kwargs['target'], list):
            target_mac = utils.get_mac_by_ip(kwargs['target'])
            for _ in xrange(6):
                sock.send(str(utils.build_arp_packet(target_mac, kwargs['gateway'], kwargs['target'])))
                sock.send(str(utils.build_arp_packet(source_mac, kwargs['target'], kwargs['gateway'])))
        else:
            for addr in kwargs['target']:
                target_mac = utils.get_mac_by_ip(addr)
                for _ in xrange(6):
                    sock.send(str(utils.build_arp_packet(target_mac, kwargs['gateway'], addr)))
                    sock.send(str(utils.build_arp_packet(source_mac, addr, kwargs['gateway'])))
