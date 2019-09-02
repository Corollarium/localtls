#!/bin/bash

echo "This script installs deps for running depserver on a Ubuntu server."

# base/certbot ppa
echo "Getting updates"
sudo apt-get install software-properties-common
sudo add-apt-repository universe
sudo add-apt-repository ppa:certbot/certbot
sudo apt-get update

# packages
echo "Installing updates"
sudo apt install mosh python3-pip certbot
sudo pip3 install dnslib cherrypy

# kill resolved
echo "Removing resolved"
echo "127.0.0.1 $(hostname)" >> /etc/hosts 
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved
rm -f /etc/resolv.conf
echo "nameserver 127.0.0.1" > /etc/resolv.conf

sudo ufw allow ssh
sudo ufw allow 53
sudo ufw allow 80
sudo ufw allow 443
sudo ufw allow 60000:61000/udp
sudo ufw enable

echo "Ready. Now run python3 dnsserver.py"