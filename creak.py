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

"""
Usage: creak.py [options] dev

Options:
  -h, --help           show this help message and exit
  -1, --sessions-scan  Sessions scan mode
  -2, --dns-spoof      Dns spoofing
  -3, --session-hijack Try to steal a TCP sessions by desynchronization (old technique)
  -x, --spoof          Spoof mode, generate a fake MAC address to be used
                       during attack
  -m MACADDR           Mac address octet prefix (could be an entire MAC
                       address in the form AA:BB:CC:DD:EE:FF)
  -M MANUFACTURER      Manufacturer of the wireless device, for retrieving a
                       manufactur based prefix for MAC spoof
  -s SOURCE            Source ip address (e.g. a class C address like
                       192.168.1.150) usually the router address
  -t TARGET            Target ip address (e.g. a class C address like
                       192.168.1.150)
  -p PORT              Target port to shutdown
  -a HOST              Target host that will be redirect while navigating on
                       target machine
  -r REDIR             Target redirection that will be fetched instead of host
                       on the target machine
  -v, --verbose        Verbose output mode
  -d, --dotted         Dotted output mode
"""

import os
import sys
import time
import random
import argparse
import creak.utils as utils
import creak.mitm as cmitm
import ConfigParser

(G, W) = (utils.G, utils.W)

def parse_arguments():
    """ parse arguments """
    parser = argparse.ArgumentParser(description='Usage: %prog [options] dev')
    parser.add_argument('-1', '--sessions-scan', action='store_const', const=1, dest='mode',
                        help='Sessions scan mode')
    parser.add_argument('-2', '--dns-spoof', action='store_const', const=2, dest='mode',
                        help='Dns spoofing')
    parser.add_argument('-3', '--hijack-session', action='store_const', const=3, dest='mode',
                        help='Session hijack through desynchronization')
    parser.add_argument('-x', '--spoof', action='store_true', default=False, dest='spoof',
                        help='Spoof mode, generate a fake MAC address to be used during attack')
    parser.add_argument('-m', dest='macaddr',
                        help='Mac address octet prefix (could be an entire MAC address in the'
                        'form AA:BB:CC:DD:EE:FF)')
    parser.add_argument('-M', dest='manufacturer',
                        help='Manufacturer of the wireless device, for retrieving a manufactur '
                        'based prefix for MAC spoof')
    parser.add_argument('-s', dest='source',
                        help='Source ip address (e.g. a class C address like 192.168.1.150) '
                        'usually the router address')
    parser.add_argument('-t', action='append', dest='target', default=[],
                        help='Target ip address (e.g. a class C address like 192.168.1.150)')
    parser.add_argument('-p', dest='port',
                        help='Target port to shutdown')
    parser.add_argument('-a', dest='host',
                        help='Target host that will be redirect while navigating on target machine')
    parser.add_argument('-r', dest='redir',
                        help='Target redirection that will be fetched instead of host on the '
                        'target machine')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, dest='verbosity',
                        help='Verbose output mode')
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        dest='debug', help='Dotted output mode')
    parser.add_argument('dev', metavar='DEV', nargs='+', help='A device to use (e.g. wlan0)')

    return parser.parse_args()

def get_mitm(parsed_args):
    """
    create an object of type Mitm based on arguments received
    """
    args = parsed_args

    if not args.dev:
        sys.exit(sys.argv[0] + ' -h for help\n[!] Must specify interface')

    dev = "%s" % "','".join(args.dev)

    original_mac_addr = utils.get_mac_by_dev(dev)
    mac_addr, changed = original_mac_addr, False

    if not args.source:
        try:
            args.source = utils.get_default_gateway_linux()
        except OSError:
            args.source = raw_input('[!] Unable to retrieve default gateway, please specify one: ')
            if not utils.is_ipv4(args.source):
                exit('[!] Unable to retrieve default gateway, please specify one using -s option')
            else:
                pass

    if not args.target:
        args.target = raw_input('[?] No target address specified, please insert one: ')
        if not utils.is_ipv4(args.target):
            exit('[!] Must specify at least one target address')
    else:
        if len(args.target) == 1:
            args.target = ''.join(args.target)

    conf = ConfigParser.ConfigParser()
    conf.read('./creak/config')
    verbose = conf.getboolean('output', 'VERBOSE')
    debug = conf.getboolean('output', 'DEBUG')

    if args.verbosity:
        verbose = True
    if args.debug:
        debug = True

    if args.spoof is True:
        choice = raw_input('[+] In order to change MAC address ' + G + dev + W
                           + ' must be temporary put down. Proceed?[y/n] ')
        if choice == 'y':
            if not args.macaddr and not args.manufacturer:
                mac_addr = utils.fake_mac_address([], 1)
            elif args.macaddr and not args.manufacturer:
                if utils.parse_mac(args.macaddr) != utils.parse_mac(original_mac_addr):
                    mac_addr = utils.fake_mac_address(utils.mac_to_hex(args.macaddr))
            elif args.manufacturer:
                macs = utils.get_manufacturer(args.manufacturer)
                mac_addr = utils.fake_mac_address(utils.mac_to_hex(random.choice(macs)))

            try:
                utils.change_mac(dev, mac_addr)
                changed = True
            except OSError:
                pass

        print("[+] Waiting for wireless reactivation..")

        if args.mode == 1 or args.mode == 2:
            time.sleep(10)
        else:
            time.sleep(4)

    # no spoof but set mac address anyway
    elif args.macaddr:
        mac_addr = args.macaddr

    print("[+] Using " + G + mac_addr + W + " MAC address\n"
          "[+] Set " + G + args.source + W + " as default gateway")

    if conf.get('output', 'ENGINE').lower() == 'scapy':
        return (args, changed, original_mac_addr,
                cmitm.ScapyMitm(dev, utils.parse_mac(mac_addr), args.source,
                                args.target, debug, verbose))
    return (args, changed, original_mac_addr,
            cmitm.PcapMitm(dev, utils.parse_mac(mac_addr), args.source,
                           args.target, debug, verbose))

def main():
    """
    Main point of access of the program
    """
    # check privileges (low level socket and pcap require root)
    if not os.geteuid() == 0:
        exit('You must be root.')

    print("")

    (args, changed, original_mac_addr, mitm) = get_mitm(parse_arguments())

    if args.mode == 1:
        mitm.list_sessions(False, args.port)

    elif args.mode == 2:
        if not args.redir:
            exit("[!] Missing redirection")
        mitm.dns_spoof(args.host, args.redir)

    elif args.mode == 3:
        mitm.hijack_session(args.source)

    else:
        if args.port:
            mitm.rst_inject(args.port)
        else:
            mitm.rst_inject()

    if changed is True:
        try:
            time.sleep(1)
            print("[+] Resetting MAC address to original value " + G + original_mac_addr + W
                  + " for device " + G + args.dev + W)
            utils.change_mac(args.dev, original_mac_addr)
        except OSError:
            pass

if __name__ == '__main__':
    exit(main())
