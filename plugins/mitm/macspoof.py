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

import os
import re
import sys
import random
import ConfigParser

if sys.version_info < (3, 0):
    import urllib2
else:
    import urllib.request

from creak.baseplugin import BasePlugin
import creak.utils as utils
import creak.config as config

(G, W) = (utils.G, utils.W)

class Plugin(BasePlugin):

    """
    """

    def init_plugin(self):
        self._set_info(
            author='codep',
            version='1.0',
            description='Change the mac address setting a spoofed one')
        self._set_required_params(dev=True, fake_addr=False, dev_brand=True)
        self._set_root(True)

    def get_manufacturer(self, manufacturer):
        """
        get a list of MAC octets based on manufacturer fetching data from
        http://anonsvn.wireshark.org/wireshark/trunk/manuf
        """
        output, m_list = [], None
        version = sys.version_info
        url_lib = None

        if version < (3, 0):
            url_lib = urllib2
        else:
            url_lib = urllib.request

        if not os.path.exists("./manufacturers"):
            os.makedirs("./manufacturers")

        if not os.path.isfile("./manufacturers/list.txt"):
            self.print_output("No local cache data found for " + G + manufacturer + W
                              + " found, fetching from web..")
            try:
                urls = url_lib.urlopen(config.MANUFACTURER_URL)
                m_list = open("./manufacturers/list.txt", "w+")

                for line in urls:
                    try:
                        mac = line.split()[0]
                        man = line.split()[1]
                        if re.search(manufacturer.lower(),
                                     man.lower()) and len(mac) < 17 and len(mac) > 1:
                            if version < (3, 0):
                                output.append(mac)
                            else:
                                output.append(mac.decode('utf-8'))

                    except IndexError:
                        pass
            except:
                self.print_error("Error occured while trying to fetch data for manufacturer based mac address")

        else:
            macs = []
            self.print_output("Fetching data from local cache..")
            conf = ConfigParser.ConfigParser()
            conf.read("./manufacturers/list.txt")

            try:
                macs = conf.get(manufacturer.lower(), 'MAC').split(',')
                if len(macs) > 0:
                    self.print_output("Found mac octets from local cache for " + G + manufacturer + W
                                      + " device")
                    return macs
            except:
                self.print_output('No MAC prefixes found from local cache,'
                                  ' for {}{}{} fetching from web'.format(G,
                                                                         manufacturer,
                                                                         W))
                urls = url_lib.urlopen(config.MANUFACTURER_URL)
                m_list = open("./manufacturers/list.txt", "a+")

                for line in urls:
                    try:
                        mac = line.split()[0]
                        man = line.split()[1]
                        if re.search(manufacturer.lower(),
                                     man.lower()) and len(mac) < 17 and len(mac) > 1:
                            if version < (3, 0):
                                output.append(mac)
                            else:
                                output.append(mac.decode('utf-8'))
                    except IndexError:
                        pass

        if len(output) > 0:
            m_list.write("[" + manufacturer.lower() + "]\nMAC = ")
            m_list.write(",".join(output))
            m_list.write("\n")
            m_list.close()

        return output

    def fake_mac_address(self, prefix, mode=None):
        """ generate a fake MAC address """
        if mode == 1:
            prefix = [0x00, 0x16, 0x3e]
            prefix += [(random.randint(0x00, 0x7f)) for _ in xrange(3)]
        else:
            prefix += [(random.randint(0x00, 0xff)) for _ in xrange(6 - len(prefix))]
        return ':'.join('%02x' % x for x in prefix)

    def change_mac(self, dev, new_mac):
        """ try to change the MAC address associated to the device """
        if os.path.exists("/usr/bin/ip") or os.path.exists("/bin/ip"):
            # turn off device
            subprocess.check_call("ip", "link", "set", "%s" % dev, "down")
            # set mac
            subprocess.check_call("ip", "link", "set", "%s" % dev, "address", "%s" % new_mac)
            # turn on device
            subprocess.check_call("ip", "link", "set", "%s" % dev, "up")
        else:
            # turn off device
            subprocess.check_call(["ifconfig", "%s" % dev, "down"])
            # set mac
            subprocess.check_call(["ifconfig", "%s" % dev, "hw", "ether", "%s" % new_mac])
            # turn on device
            subprocess.check_call(["ifconfig", "%s" % dev, "up"])
            # restart network
            if config.NETWORK_RESTART == config.SYSTEMD_NETWORK:
                subprocess.check_call([config.NETWORK_RESTART])
            else:
                subprocess.check_call([config.NETWORK_RESTART, "restart"])

    def run(self, kwargs):
        dev_brand = 0
        if 'dev_brand' in kwargs:
            dev_brand = kwargs['dev_brand']

        print('')
        self.print_output('In order to change MAC address ' + G +
                         kwargs['dev'] + W + ' must be temporary put down.')
        choice = raw_input('Proceed? [y/n] ')

        if choice == 'y' or choice == 'yes':
            mac_addr = utils.fake_mac_address([], 1)
            if dev_brand != 0 and not 'fake_addr' in kwargs:
                macs = self.get_manufacturer(dev_brand)
                self.print_output('Found {} MAC prefix for {} brand'.format(len(macs), dev_brand))
                self.print_output('Choosing one randomly')
                if len(macs) > 0:
                    mac_addr = utils.fake_mac_address(utils.mac_to_hex(random.choice(macs)))
            elif dev_brand != 0 and 'fake_addr' in kwargs:
                if utils.parse_mac(kwargs['mac_addr']) != utils.parse_mac(kwargs['fake_addr']):
                    mac_addr = utils.fake_mac_address(utils.mac_to_hex(kwargs['fake_addr']))

            self.print_output('New MAC address {} is set'.format(mac_addr))
            print('')
            # try:
            #     utils.change_mac(kwargs['dev'], mac_addr)
            # except OSError:
            #     self.print_exception()

