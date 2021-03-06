#!/usr/bin/bash

systemctl stop NetworkManager
airmon-ng check kill
ifconfig wlp3s0 10.0.0.1 netmask 255.255.255.0
route add default gw 10.0.0.1

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT

dnsmasq -C dnsmasq.conf
hostapd hostapd.conf -B 
echo "Starting apache server"
sudo systemctl start httpd



