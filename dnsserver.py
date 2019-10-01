#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

import json
import logging
import os
import sys
import signal
import re
import socket
import argparse
import ipaddress
from datetime import datetime
from time import sleep
import threading
from multiprocessing.connection import Listener

import dnslib
from dnslib import DNSLabel, QTYPE, RR, dns
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer, DNSLogger

import httpserver
import confs 

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s', datefmt='%H:%M:%S'))
logger = logging.getLogger('localtls')
logger.addHandler(handler)

TYPE_LOOKUP = {
    'A': (dns.A, QTYPE.A),
    'AAAA': (dns.AAAA, QTYPE.AAAA),
    'CAA': (dns.CAA, QTYPE.CAA),
    'CNAME': (dns.CNAME, QTYPE.CNAME),
    'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
    'MX': (dns.MX, QTYPE.MX),
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
    'NS': (dns.NS, QTYPE.NS),
    'PTR': (dns.PTR, QTYPE.PTR),
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
    'SOA': (dns.SOA, QTYPE.SOA),
    'SRV': (dns.SRV, QTYPE.SRV),
    'TXT': (dns.TXT, QTYPE.TXT),
    'SPF': (dns.TXT, QTYPE.TXT),
}

TXT_RECORDS = {}

def get_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = ''
    finally:
        s.close()
    return IP

def get_ipv6():
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    try:
        s.connect(('2001:0db8:85a3:0000:0000:8a2e:0370:7334', 1))
        IP = s.getsockname()[0]
    except:
        IP = ''
    finally:
        s.close()
    return IP

class Resolver(ProxyResolver):
    def __init__(self, upstream):
        super().__init__(upstream, 53, 5)
        if confs.SOA_MNAME and confs.SOA_RNAME:
            self.SOA = dnslib.SOA(
                mname=DNSLabel(confs.SOA_MNAME),
                rname=DNSLabel(confs.SOA_RNAME.replace('@', '.')), # TODO: . before @ should be escaped
                times=(
                    confs.SOA_SERIAL,  # serial number
                    60 * 60 * 1,  # refresh
                    60 * 60 * 2,  # retry
                    60 * 60 * 24,  # expire
                    60 * 60 * 1,  # minimum
                )
            )
        else:
            self.SOA=None

        if confs.NS_SERVERS:
            self.NS = [dnslib.NS(i) for i in confs.NS_SERVERS]
        else:
            self.NS = []

    def resolve(self, request, handler):
        global TXT_RECORDS
        reply = request.reply()
        name = request.q.qname
        logger.info("query %s", request.q.qname)

        # handle the main domain
        if (name == confs.BASE_DOMAIN or 
            name == '_acme-challenge.' + confs.BASE_DOMAIN
        ):
            r = RR(
                rname=request.q.qname,
                rdata=dns.A(confs.LOCAL_IPV4),
                rtype=QTYPE.A,
                ttl=60*60
            )
            reply.add_answer(r)

            if self.SOA:
                r = RR(
                    rname=request.q.qname,
                    rdata=self.SOA,
                    rtype=QTYPE.SOA,
                    ttl=60*60
                )
                reply.add_answer(r)

            if len(self.NS):
                for i in self.NS:
                    r = RR(
                        rname=request.q.qname,
                        rdata=i,
                        rtype=QTYPE.NS,
                        ttl=60*60
                    )
                    reply.add_answer(r)

            if confs.LOCAL_IPV6:
                r = RR(
                    rname=request.q.qname,
                    rdata=dns.AAAA(confs.LOCAL_IPV6),
                    rtype=QTYPE.AAAA,
                    ttl=60*60
                )
                reply.add_answer(r)

            if len(TXT_RECORDS):
                r = RR(
                    rname=request.q.qname,
                    rdata=dns.TXT(['{1}'.format(k, v) for k, v in TXT_RECORDS.items()]),
                    rtype=QTYPE.TXT
                )
                reply.add_answer(r)
            return reply
        # handle subdomains
        elif name.matchSuffix(confs.BASE_DOMAIN): # fnmatch
            labelstr = str(request.q.qname)
            logger.info("requestx: %s, %s", labelstr, confs.ONLY_PRIVATE_IPS)

            subdomains = labelstr.split('.')
            print(subdomains)
            if len(subdomains) == 4: # TODO: dynamic
                ip = None
                try:
                    ip = ipaddress.ip_address(subdomains[0].replace('-', '.'))
                except:
                    pass
                try:
                    if ip == None:
                        ip = ipaddress.ip_address(subdomains[0].replace('-', ':'))
                except:
                    logger.info('invalid ip %s', labelstr)
                    return reply

                # check if we only want private ips
                if not ip.is_private and confs.ONLY_PRIVATE_IPS:
                    return reply
                # check if it's a valid ip for a machine
                if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                    return reply

                if type(ip) == ipaddress.IPv4Address:
                    ipv4 = subdomains[0].replace('-', '.')
                    logger.info("ip is ipv4 %s", ipv4)
                    r = RR(
                        rname=request.q.qname,
                        rdata=dns.A(ipv4),
                        rtype=QTYPE.A,
                        ttl=24*60*60
                    )
                    reply.add_answer(r)
                elif type(ip) == ipaddress.IPv6Address:
                    ipv6 = subdomains[0].replace('-', ':')
                    logger.info("ip is ipv6 %s", ipv6)
                    r = RR(
                        rname=request.q.qname,
                        rdata=dns.AAAA(ipv6),
                        rtype=QTYPE.AAAA,
                        ttl=24*60*60
                    )
                    reply.add_answer(r)
                else:
                    return reply
            
                logger.info('found zone for %s, %d replies', request.q.qname, len(reply.rr))
            return reply

        return super().resolve(request, handler)


def handle_sig(signum, frame):
    logger.info('pid=%d, got signal: %s, stopping...', os.getpid(), signal.Signals(signum).name)
    exit(0)

# this is used to hear for new TXT records from the certbotdns script. We need to get them ASAP to
# validate the certbot request.
def messageListener():
    global TXT_RECORDS
    address = ('localhost', 6000)     # family is deduced to be 'AF_INET'
    listener = Listener(address, authkey=os.getenv('KEY', b'secret')) # not very secret, but we're bound to localhost.
    while True:
        conn = None
        try:
            conn = listener.accept()
            msg = conn.recv()
            # do something with msg
            msg = json.loads(msg, encoding="utf-8")
            if msg['command'] == "ADDTXT":
                TXT_RECORDS[msg["key"]] = msg["val"]
            elif msg['command'] == "REMOVETXT":
                TXT_RECORDS.pop(msg["key"])
            conn.close()
        except Exception as e:
            logger.error(e)
            if conn: 
                conn.close()
            pass
    listener.close()

def main():
    signal.signal(signal.SIGTERM, handle_sig)

    parser = argparse.ArgumentParser(description='LocalTLS')
    parser.add_argument(
        '--domain',
        required = True,
        help = "Your domain or subdomain."
    )
    parser.add_argument(
        '--soa-master',
        help = "Primary master name server for SOA record. You should fill this."
    )
    parser.add_argument(
        '--soa-email',
        help = "Email address for administrator for SOA record. You should fill this."
    )
    parser.add_argument(
        '--ns-servers',
        help = "List of ns servers, separated by comma"
    )
    parser.add_argument(
        '--dns-port',
        default=53,
        help = "DNS server port"
    )
    parser.add_argument(
        '--domain-ipv4',
        default='',
        help = "The IPV4 for the naked domain. If empty, use this machine's."
    )
    parser.add_argument(
        '--domain-ipv6',
        default='',
        help = "The IPV6 for the naked domain. If empty, use this machine's."
    )
    parser.add_argument(
        '--only-private-ips',
        action='store_true',
        default=False,
        help = "Resolve only IPs in private ranges."
    )
    parser.add_argument(
        '--dns-fallback',
        default='1.1.1.1',
        help = "DNS fallback server. Default: 1.1.1.1"
    )
    parser.add_argument(
        '--http-port',
        help = "HTTP server port. If not set, no HTTP server is started"
    )
    parser.add_argument(
        '--http-index-file',
        default = 'index.html',
        help = "HTTP index.html file."
    )
    parser.add_argument(
        '--log-level',
        default = 'ERROR',
        help = "INFO|WARNING|ERROR|DEBUG"
    )
    args = parser.parse_args()

    # The primary addresses
    confs.LOCAL_IPV4 = args.domain_ipv4 if args.domain_ipv4 else get_ipv4()
    confs.LOCAL_IPV6 = args.domain_ipv6 if args.domain_ipv6 else get_ipv6()
    try:
        ipaddress.ip_address(confs.LOCAL_IPV4)
    except:
        logger.critical('Invalid IPV4 %s', LOCAL_IPV4)
        sys.exit(1)
    try:
        if confs.LOCAL_IPV6:
            ipaddress.ip_address(confs.LOCAL_IPV6)
    except:
        logger.critical('Invalid IPV6 %s', LOCAL_IPV6)
        sys.exit(1)
    logger.setLevel(args.log_level)

    confs.ONLY_PRIVATE_IPS = args.only_private_ips
    confs.BASE_DOMAIN = args.domain
    confs.SOA_MNAME = args.soa_master
    confs.SOA_RNAME = args.soa_email
    if not confs.SOA_MNAME or not confs.SOA_RNAME:
        logger.error('Setting SOA is strongly recommended')
        
    if args.ns_servers:
        confs.NS_SERVERS=args.ns_servers.split(',')

    # handle local messages to add TXT records
    threadMessage = threading.Thread(target=messageListener)
    threadMessage.start()

    # open the DNS server
    port = int(args.dns_port)
    upstream = args.dns_fallback
    resolver = Resolver(upstream)
    if args.log_level == 'debug':
        logmode = "+request,+reply,+truncated,+error"
    else:
        logmode = "-request,-reply,-truncated,+error"
    dnslogger = DNSLogger(log=logmode, prefix=False)
    udp_server = DNSServer(resolver, port=port, logger=dnslogger)
    tcp_server = DNSServer(resolver, port=port, tcp=True, logger=dnslogger)

    logger.critical('starting DNS server on %s/%s on port %d, upstream DNS server "%s"', confs.LOCAL_IPV4, confs.LOCAL_IPV6, port, upstream)
    udp_server.start_thread()
    tcp_server.start_thread()

    # open the HTTP server
    if args.http_port:
        logger.critical('Starting httpd...')
        threadHTTP = threading.Thread(target=httpserver.run, kwargs={"port": int(args.http_port), "index": args.http_index_file})
        threadHTTP.start()

    try:
        while udp_server.isAlive():
            sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
     main()
