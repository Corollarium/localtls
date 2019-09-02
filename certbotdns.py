#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

import os
import sys
import json
import subprocess
from multiprocessing.connection import Client

# To simulate certbot DNS hooks:
# CERTBOT_DOMAIN=yourdomain.net CERTBOT_VALIDATION=xxx python3 certbottxt.py deploy
# CERTBOT_DOMAIN=yourdomain.net CERTBOT_VALIDATION=xxx CERTBOT_AUTH_OUTPUT=_acme-challenge.asdf.com python3 certbottxt.py cleanup

BASE_PATH=os.path.realpath(__file__)
CERTBOT_DOMAIN=os.getenv('CERTBOT_DOMAIN')
CERTBOT_VALIDATION=os.getenv('CERTBOT_VALIDATION')

from multiprocessing.connection import Client

address = ('localhost', 6000)

def help():
    print("Command: renovate [domain] [email]\n")

if len(sys.argv) == 1:
    help()
elif sys.argv[1] == 'deploy':
    DOMAIN="_acme-challenge.%s" % CERTBOT_DOMAIN
    conn = Client(address, authkey=b'secret')
    conn.send(json.dumps({'command': 'ADDTXT', 'key': DOMAIN, 'val': CERTBOT_VALIDATION}, ensure_ascii=False, indent=4))
    print(DOMAIN)
    conn.close()
elif sys.argv[1] == 'cleanup':
    CERTBOT_AUTH_OUTPUT=os.getenv('CERTBOT_AUTH_OUTPUT', '*')
    conn = Client(address, authkey=b'secret')
    conn.send(json.dumps({'command': 'REMOVETXT', 'key': CERTBOT_AUTH_OUTPUT}, ensure_ascii=False, indent=4))
    conn.close()
elif sys.argv[1] == 'wildcard' or sys.argv[1] == 'naked':
    if len(sys.argv) != 4:
        help()
    else:
        script = os.path.abspath(__file__)
        basename = sys.argv[2] + '-' + sys.argv[1]
        command = [
            'certbot', 'certonly', '--noninteractive', '--test-cert',
            '--agree-tos', '--email', sys.argv[3],
            '--manual', '--preferred-challenges=dns', '--manual-public-ip-logging-ok',
            '--manual-auth-hook', 'python3 {0} deploy'.format(script), 
            '--manual-cleanup-hook', 'python3 {0} cleanup'.format(script),
            '-d', ('*.' if sys.argv[1] == 'wildcard' else '') + sys.argv[2]
        ]
        output = subprocess.run(command)
        print(output.stdout)
        print(output.stderr)
