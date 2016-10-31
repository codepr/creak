# -*- coding: utf-8 -*-
""" general configuration file """
SCAPY                    = False
VERBOSE                  = False
DOTTED                   = False
# ip_forward path
IP_FORWARD               = '/proc/sys/net/ipv4/ip_forward'
# manufacturer list url (wireshark)
MANUFACTURER_URL         = 'http://anonsvn.wireshark.org/wireshark/trunk/manuf'
# network service common path
UBUNTU_DEB_STD           = '/etc/init.d/networking'
UBUNTU_DEB_SERVICE       = 'service networking'
UBUNTU_DEB_NSERVICE      = 'service network-manager'
RHEL_FEDORA_CENTOS       = '/etc/init.d/network'
RHEL_FEDORA_CENTOS_SERV  = 'service network'
SLACKWARE_GENTOO_GENERIC = '/etc/rc.d/rc.init1'
SLACKWARE_GENTOO_NETWORK = '/etc/rc.d/rc.networkmanager'
SYSTEMD_NETWORK          = 'systemctl restart systemd-networkd.service'
# change accordingly to system preferences to restart network
NETWORK_RESTART          = SYSTEMD_NETWORK
