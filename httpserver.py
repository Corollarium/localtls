# -*- coding: utf-8 -*-

import os
import sys
import confs
import cherrypy

INDEX_HTML='<html><body>Hi.</body></html>'
CERT_PATH= os.path.dirname(os.path.realpath(__file__)) # TODO

class Root(object):
    @cherrypy.expose
    def index(self):
        return INDEX_HTML

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def keys(self):
        privkey = cert = chain = fullchain = ''
        try:
            with open(os.path.join(CERT_PATH, 'cert.pem')) as f:
                cert = f.read()
            with open(os.path.join(CERT_PATH, 'chain.pem')) as f:
                chain = f.read()
            with open(os.path.join(CERT_PATH, 'fullchain.pem')) as f:
                fullchain = f.read()
            with open(os.path.join(CERT_PATH, 'privkey.pem')) as f:
                privkey = f.read()
        except ValueError as e:
            print(str(e))
        except FileNotFoundError as e:
            print(str(e))
        except:
            print("Unexpected error:", sys.exc_info()[0])
        return {'privkey': privkey, 'cert': cert, 'chain': chain, 'fullchain': fullchain}

    @cherrypy.expose
    def favicon_ico(self):
        raise cherrypy.HTTPError(404)

def run(port, index, certpath=''):
    global INDEX_HTML, CERT_PATH
    try:
        with open(index) as f:
            INDEX_HTML=bytes(f.read(), "utf8")
    except:
        pass

    cherrypy.config.update({
        'log.screen': False,
        'log.access_file': '',
        'log.error_file': '',
        'environment': 'production',
        'server.socket_port': int(port)
    })
    
    if port == 443:
        cherrypy.config.update({
            'server.ssl_module': 'builtin',
            'server.ssl_certificate': "cert.pem",
            'server.ssl_private_key': "privkey.pem",
            'server.ssl_certificate_chain': "certchain.perm"
        })

    cherrypy.quickstart(Root(), '/')
