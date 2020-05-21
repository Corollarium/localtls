# localtls

This is a simple DNS server in Python3 to provide TLS to webservices on local addresses. In short, it resolves addresses such as '192-168-0-1.yourdomain.net' to 192.168.0.1 and has a valid TLS certificate for them.

This was written to circumvent the problem that current browsers require a secure context for a number of operations, such as opening the camera with `getUserMedia`, but the web service is running on a local network, where it is difficult to get a certificate or handling the local DNS servers is difficult or impossible (aham users aham). It can also be used to easily develop and debug web applications that require secure contexts other than in localhost.

Technically it's a very simple DNS server written in Python, which uses [Let's Encrypt](https://letsencrypt.org/) to generate a wildcard certificate for *.yourdomain.net on a real public server. This certificate, both private and public keys, is available for download via a REST call on a simple HTTP server also provided.

## Technical explanation and motivation

Browsers require <a href="https://w3c.github.io/webappsec-secure-contexts/">a secure context</a> (<a href="https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts">MDN</a>) for several Web APIs to work. While this is simple for public websites, it is a difficult issue for intranets and private IPs. When you're deploying applications on networks that you have no control, it's a nightmare.

This software provides:

1. a simple DNS server that resolves to IP.yourdomain.net (for local IPs, see below) to IP and should run on a public internet server.
1. an embedded simple HTTP server showing an index.html and with a REST endpoint with the certificate keys, including the private key.
1. a one-liner to generate and renew a valid certificate with LetsEncrypt, using DNS authentication. This script should be run once a month.

## What this DNS resolves

* yourdomain.net: to your server IP, both A and AAAA (if it exists) records.
* _acme-challenge.yourdomain.net also resolves like this, since it's necessary for the certbot authentication.
* a-b-c-d.yourdomain.net, where a.b.c.d is a valid private network IPV4 (192.168.0.0–192.168.255.255, 172.16.0.0–172.31.255.255 and 10.0.0.0–10.255.255.255): resolves to A record of a.b.c.d. In other words, replace `.` by `-`.
* fe80-[xxx].yourdomain.net: resolves to AAAA record of fe80:[xxx]. In other words, replace any `:` by `-`.
* anything else: falls back to another DNS server.

## Security considerations

"But if you provide the public and the private key, someone can do a man-in-the-middle attack!" Yes, that is correct. This is *as safe as a plain HTTP website if you release the private key*. 

This service here aims to solve the *requirement of browsers with secure contexts in LANs with a minimum fuss*: when you are developing an app that requires TLS, for example, and want to test it on several devices locally. Or when you want to deploy a web application on customer networks that have no expertise. Hopefully browsers will come up with a solution that makes secure contexts in intranets easier in the future, but it has been a problem for years and it's still unsolved at this time.

In short, you have two possible scenarios. The first: you understand that by using this you may be prone for a MITM attack, but you need a secure context in the browser no matter what, and you do need absolute certainty that your traffic will not be snooped or your application won't be spoofed. This works for most webservices running in a LAN, and is as safe as running them on pure HTTP.

The second: you need not only a secure context for the browser, but actual safety of a private TLS certificate validated by the browser. In this case you can run the DNS server yourself and not publish the private keys, but find someway to distribute them yourself privately to your application. Remember, any application you deploy using TLS will require a private key deployed with it. When distributing web apps that are supposed to run in intranets which you have no access this is hard to do; you'd ideally need to generate a different key for every host, even though they may use the same private IP, you have no accessto a local nameserver and other complications. There is a [nice proposal of how this can be done](https://blog.heckel.io/2018/08/05/issuing-lets-encrypt-certificates-for-65000-internal-servers/) if you need this level of security.

# How to Run

## Overview

1. Get a server. It doesn't need to be big. Ideally you should have at least one slave, too, because NS entries require at least two servers.
1. Point the NS entry of your domain to this server.
1. [Install deps](#base-installation-and-deps).
1. [Run dnsserver.py](#running-the-dns-server).
1. [Create the certificates running certbotdns.py](#renewing-keys).

## Base installation and deps

You essentially need Python 3.6 or above, certbot and the dnslib and cherrypy PIPs.

We provide a simple `util/ubuntu-install.bash` script that installs all you need to be able to run this software on a fresh Ubuntu installation. Notice it will kill the default nameserver, so you'll have no DNS resolving after your run it. Just start localtls after that. And hey, if you are running your own DNS server you should know what to do anyway.

## Running the DNS server

You probably want to start dnsserver in production like this:

`python3 dnsserver.py --domain yourdomain.net --soa-master=ns1.yourdomain.net --soa-email=email@yourdomain.net --ns-servers=ns1.yourdomain.net,ns2.yourdomain.net --log-level ERROR --http-port 80 --http-index /somewhere/index.html` 

Run `python3 dnsserver.py --help` for a list of arguments.

* `--domain`: REQUIRED. Your domain or subdomain.
* `--soa-master`: STRONGLY RECOMMENDED. Primary master name server for SOA record. You should fill this to be compliant to RFC 1035. 
* `--soa-email`: STRONGLY RECOMMENDED. Email address for administrator for SOA record. You should fill this to be compliant to RFC 1035.
* `--ns-servers`: STRONGLY RECOMMENDED. The list of nameservers, separated by commas, for the NS record.
* `--dns-port`: DNS server port. Defaults to 53. You need to be root on linux to run this on a port < 1024.
* `--dns-fallback`: The DNS fallback server. This server can be used as full DNS resolver in your network, falling back to this server.
* `--domain-ipv4`: The ipv4 for the naked domain. Defaults to the server IPV4. 
* `--domain-ipv6`: The ipv6 for the naked domain. Defaults to the server IPV6.
* `--http-port`: the HTTP server port. If not set, no HTTP server is started. The HTTP server is used to serve a index.html for the `/` location and the `/keys` with the keys.
* `--http-index-file`: path to the HTTP index html. We don't serve assets. The file is read upon start and cached. 
* `--log-level`: INFO|WARNING|ERROR|DEBUG. You should run on ERROR level in production.
* `--only-private-ips`: Only resolve private ips.
* `--no-reserved-ips`: Don't resolve reserved ips.


This software uses port 6000 for internal communication. It is bound to 127.0.0.1.

## Slave DNS server

To run a secondary NS server, we suggest run dnsserver.py without a HTTP server. Remember to set `--domain-ipv4` and `--domain-ipv6` pointing to the master server. Do not run certbotdns.py on the slave servers.

### Testing

Run locally like this for a minimal test at port 5300:

`python3 dnsserver.py --domain=yourdomain.net --dns-port=5300`

Run dig to test:

`dig @localhost -p 5300 +nocmd 192-168-0-255.yourdomain.net ANY +multiline +noall +answer`

## Renewing keys

You should renew keys once a month, according to the recommendation of Let's Encrypt. Run this with the proper domain: 

`python3 certbotdns.py wildcard yourdomain.net email@yourdomain.net`

If you wish to generate a certificate for the naked domain 
`python3 certbotdns.py naked yourdomain.net email@yourdomain.net`


Here's a cron line to run it monthly: 

`0 0 1 * * python3 /path/to/certbotdns.py wildcard yourdomain.net email@yourdomain.net; python3 /path/to/certbotdns.py naked yourdomain.net email@yourdomain.net`

# Using this in your webservice

We at [Corollarium](https://corollarium.com) are using it at [videowall.online](https://videowall.online). It's used in our [video wall](https://softwarevideowall.com).

You should fetch the keys remotely before you open your webservice. Keys are valid for three months, but renewed every month. If your service runs continuously for longer than that you should either restart the service or make it poll and replace the keys every 24h or so.

First, make sure you run with `--http-port`. Make a REST GET rest for `[DOMAIN]/keys` and you'll get a JSON with the following keys:

* privkey: the private key.
* cert: the public certificate.
* chain: the chain certificate.
* fullchain: the full chain certificate.

This follows the same pattern of files created by Let's Encrypt.

## Node.js code

This code will try to get the keys until a timeout and open a HTTPS server using those keys locally. Remember to replace `yourdomain.net`.

```
function localtls(dnsserver) {
	const request = require('request');
	return new Promise(function(resolve, reject) {
		request({
			uri: dnsserver + '/keys',
			timeout: 10000,
		}, function (error, response, body) {
			if (error) {
				reject(error);
			}
			else {
				try {
					let d = JSON.parse(body);
					resolve({key: d.privkey, cert: d.cert, ca: d.chain});
				}
				catch (e) {
					reject(e);
				}
			}
		});
	});
}

var app = express(), https;
try {
	let keys = await localtls('http://yourdomain.net');

	// reload keys every week, see https://github.com/nodejs/node/issues/15115
	let ctx = tls.createSecureContext(keys);
	setInterval(() => {
		lantls().then((k) => { keys = k; }).catch(e => {});
	}, 7*24*60*60*1000);

	https = require('https').createServer({
		SNICallback: (servername, cb) => {
			cb(null, ctx);
		}
	}, app);
}
catch(e) {
	// pass
	console.log("invalid https", e);
}
```
	

# About and credits

* Developed by [Corollarium](https://corollarium.com) and released under the MIT license.
* Inspiration from [nip.io](https://nip.io), [SSLIP](https://sslip.io) and [XIP](http://xip.io/)
* [Blog post explaining how to generate certificates per server](https://blog.heckel.io/2018/08/05/issuing-lets-encrypt-certificates-for-65000-internal-servers/)
