# -*- coding: utf-8 -*-

from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import sys
import ssl
import json
import confs

INDEX_HTML='<html><body>Hi.</body></html>'.encode()

class HTTPHandler(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        if self.path == '/keys':
            self.send_header('Content-type', 'text/json')
        else:
            self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        global INDEX_HTML
        self._set_headers()
        if self.path == '/keys':
            privkey = cert = chain = fullchain = ''
            try:
                with open('/etc/letsencrypt/live/' + confs.BASE_DOMAIN + '-0001/cert.pem') as f:
                    cert = f.read()
                with open('/etc/letsencrypt/live/' + confs.BASE_DOMAIN + '-0001/chain.pem') as f:
                    chain = f.read()
                with open('/etc/letsencrypt/live/' + confs.BASE_DOMAIN + '-0001/fullchain.pem') as f:
                    fullchain = f.read()
                with open('/etc/letsencrypt/live/' + confs.BASE_DOMAIN + '-0001/privkey.pem') as f:
                    privkey = f.read()
            except ValueError as e:
                print(str(e))
            except:
                print("Unexpected error:", sys.exc_info()[0])
            self.wfile.write(
                bytes(json.dumps({'privkey': privkey, 'cert': cert, 'chain': chain, 'fullchain': fullchain}), "utf8")
            )
        else:
            self.wfile.write(INDEX_HTML)

    def do_HEAD(self):
        self._set_headers()
        
def run(port, index):
    global INDEX_HTML
    try:
        with open(index) as f:
            INDEX_HTML=bytes(f.read(), "utf8")
    except:
        pass

    server_address = ('', port)
    httpd = HTTPServer(server_address, HTTPHandler)
    if port == 443:
        httpd.socket = ssl.wrap_socket(
            httpd.socket, 
            keyfile="path/to/key.pem", # TODO  
            certfile='path/to/cert.pem', # TODO
            server_side=True
        )
    httpd.serve_forever()