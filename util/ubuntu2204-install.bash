#!/bin/bash

echo "This script will now install deps on your Ubuntu server..."

# packages
echo "Installing python, certbot and other DNS related libraries..."
sudo apt -yq install mosh python3-pip certbot
sudo pip3 install dnslib cherrypy

# kill resolved
echo "Stopping resolved from using port 53..."

# thanks https://www.linuxuprising.com/2020/07/ubuntu-how-to-free-up-port-53-used-by.html
sudo cat > /etc/systemd/resolved.conf << EOF
[Resolve]
DNS=1.1.1.1
#FallbackDNS=
#Domains=
#LLMNR=no
#MulticastDNS=no
#DNSSEC=no
#DNSOverTLS=no
#Cache=no
DNSStubListener=no
#ReadEtcHosts=yes
EOF
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

echo "Securing system with ufw..."
sudo ufw allow ssh
sudo ufw allow 53
sudo ufw allow 80
sudo ufw allow 443
sudo ufw allow 60000:61000/udp
sudo ufw enable

echo "Please reboot your system after which you are ready to run python3 dnsserver.py"