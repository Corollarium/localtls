# localtls

This is a simple DNS server in Python3 for providing TLS to webservices on local addresses. 

This was written to circumvent the problem that current browsers require a secure context for a number of operations, such as opening the camera with `getUserMedia`, but the web service is running on a local network. It can also be used to develop and debug applications that require secure contexts.

It's a very simple DNS server written in Python, which uses [Let's Encrypt](https://letsencrypt.org/) to generate a wildcard certificate for *.domain.com. This certificate, both private and public keys, is available for download via a REST call.

## Technical explanation and motivation

Browsers require <a href="https://w3c.github.io/webappsec-secure-contexts/">a secure context</a>
(<a href="https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts">MDN</a>)  
for several Web APIs to work. While this is simple for public websites, it is a difficult issue for
intranets and private IPs.

This software provides:
1. a simple DNS server that resolves to IP.yourdomain.com (with dots replaced by dashes) to IP.
2. a one-liner to generate and renew a valid certificate with LetsEncrypt, using DNS authentication. This script should be run every two months at least, but we suggest once a month.
3. a simple HTTP server showing this help and with an endpoint with the certificate keys, including the private key.

## Security considerations

"But if you provide the public and the private key, someone can do a man-in-the-middle attack!" Yes, that is correct. This is *as safe as a plain HTTP website if you release the private key*. 

This service here aims to solve the *requirement of browsers with secure contexts in LANs with a minimum fuss*: when you are developing an app that requires TLS, for example, and want to test it on several devices. Hopefully browsers will come up with a solution that makes secure contexts in intranets easier in the future, but it has been a problem for years and it's still unsolved.

In short, you have two possible scenarios. The first: you understand that by using this you may be prone for a MITM attack, but you need a secure context in the browser more than you need absolute certainty that your traffic will not be snooped or your application won't be spoofed. This works for most webservices running in a LAN, and is as safe as running them on pure HTTP.

The second: you need not only a secure context for the browser, but actual safety of a TLS certificate validated by the browser. In this case run the DNS server yourself and do not publish the private keys, but find someway to distribute them yourself privately to your application. Remember, any application you deploy using TLS will require a private key deployed with it. When distributing web apps that are supposed to run in intranets which you have no access this is hard to do; you'd ideally need to generate a different key for every host, even though they may use the same private IP, you have no accessto a local nameserver and other complications. There is a (nice proposal of how this can be done)[https://blog.heckel.io/2018/08/05/issuing-lets-encrypt-certificates-for-65000-internal-servers/] if you need this level of security.

# How to Run

## Base install

You essentially need Python3, certbot and the dnslib, python-daemon and lockfile PIPs.

We provide a simple install.bash script that installs all you need to run this software in an Ubuntu installation. And hey, if you are running your own DNS server you should know what to do anyway.

## The server

Run: `python3 dnsserver.py`.

Run `python3 dnsserver.py --help` for a list of arguments.

* `--domain`: REQUIRED. Your domain or subdomain.
* `--dns-port`: DNS server port.
* `--dns-fallback`: The DNS fallback server. This server can be used as full DNS resolver in your network, falling back to this server.
* `--http-port`: the HTTP server port. If not set, no HTTP server is started. The HTTP server is used to serve a index.html for the `/` location and the `/keys` with the keys.
* `--log-level`: INFO|WARNING|ERROR|DEBUG.

## Testing

Run locally with:

`python3 dnsserver.py --dns-port=5300`

Run dig to test:

`dig @localhost -p 5300 +nocmd 192-168-0-255.yourdomain.net ANY +multiline +noall +answer`

## Renewing keys

You should renew keys once a month, according to the recommendation of Let's Encrypt. To simulate certbot DNS hooks:

`CERTBOT_DOMAIN=yourdomain.net CERTBOT_VALIDATION=xxx python3 certbottxt.py deploy`
`CERTBOT_DOMAIN=yourdomain.net CERTBOT_VALIDATION=xxx CERTBOT_AUTH_OUTPUT=_acme-challenge.asdf.com python3 certbottxt.py cleanup`

# Using keys in your webservice

You should fetch the keys remotely before you open your webservice. Keys are valid for three months, but renewed every month. If your service runs continuously for longer than that you should either restart the service or make it poll and replace the keys every 24h or so.

First, make sure you run with `--http-port`. Make a REST GET rest for `[DOMAIN]/keys` and you'll get a JSON with the following keys:

* privkey: the private key.
* cert: the public certificate.
* chain: the chain certificate.
* fullchain: the full chain certificate.

This follows the same pattern of files created by Let's Encrypt.
