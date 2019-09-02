#-*- coding: utf-8 -*-

import os
import sys
import confs
import cherrypy
import subprocess
import logging

INDEX_HTML='<html><body>Hi.</body></html>'
CERT_PATH='/etc/letsencrypt/live/' + confs.BASE_DOMAIN
logger = logging.getLogger('localtls')

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
            cherrypy.log(str(e))
        except FileNotFoundError as e:
            cherrypy.log(str(e))
        except:
            cherrypy.log("Unexpected error:", sys.exc_info()[0])
        return {'privkey': privkey, 'cert': cert, 'chain': chain, 'fullchain': fullchain}

    @cherrypy.expose
    def favicon_ico(self):
        raise cherrypy.HTTPError(404)

def listCertificates():
    command = [
        'certbot', 'certificates'
    ]
    output = subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
    current_certificate = ''
    current_domain = ''
    paths = {}
    for line in iter(output.stdout.readline,''):
        if line.find('Certificate Name') > -1:
            current_certificate = line.split(':')[1].strip()
            continue
        elif line.find('Domains') > -1:
            domains = line.split(':')[1].strip()
            current_domain = domains
        elif line.find('Certificate Path') > -1:
            p = line.split(':')[1].strip()
            paths[domains] = os.path.dirname(p) 
    return paths

def force_tls(self=None):
    # check if url is in https and redirect if http
    if cherrypy.request.scheme == "http":
        raise cherrypy.HTTPRedirect(cherrypy.url().replace("http:", "https:"), status=301)

def run(port, index, certpath=''):
    global INDEX_HTML, CERT_PATH
    try:
        with open(index) as f:
            INDEX_HTML=bytes(f.read(), "utf8")
    except:
        pass

    # get certificates
    try:
        paths = listCertificates()
        if ('*.' + confs.BASE_DOMAIN) in paths:
            CERT_PATH = paths['*.' + confs.BASE_DOMAIN]
        else:
            logger.critical("Cannot find wildcard certificate, HTTP is quitting")
            return
    except:
        logger.critical("Cannot list certificates: {}. Run certbotdns.py now and then restart this. Meanwhile HTTP will not work.".format(sys.exc_info()[0]))
        return
    
    cherrypy.config.update({
        #'log.screen': False,
        #'log.access_file': '',
        #'log.error_file': 'http_error_log',
        #'environment': 'production',
        'server.socket_host': '0.0.0.0',
        'server.socket_port': int(port)
    })
    
    if port == 443 and confs.BASE_DOMAIN in paths:
        logger.info('Starting TLS server.')
        cert = paths[confs.BASE_DOMAIN]
        cherrypy.tools.force_tls = cherrypy.Tool("before_handler", force_tls)
        cherrypy.config.update({
            'server.ssl_module': 'builtin',
            'server.ssl_certificate': os.path.join(cert, "cert.pem"),
            'server.ssl_private_key': os.path.join(cert, "privkey.pem"),
            'server.ssl_certificate_chain': os.path.join(cert, "fullchain.pem"),
            'tools.force_tls.on': True
        })

        # extra server instance to dispatch HTTP
        server = cherrypy._cpserver.Server()
        server.socket_host = "0.0.0.0"
        server.socket_port = 80
        server.subscribe()

    logger.info('Starting HTTP server.')
    cherrypy.quickstart(Root(), '/')
