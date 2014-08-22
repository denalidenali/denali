#!/usr/bin/sh
#This script runs on the server (transmitter)
#It creates a TUN interface and sets the subnet
#Then creates two virtual monitor interfaces 
sudo openvpn --mktun --dev tun2
sudo ip link  set tun2 up 
sudo ip addr add 10.0.0.2/24 dev tun2 

sudo iw phy phy0 interface add phy0 type monitor flags fcsfail 
sudo iw phy phy1 interface add phy1 type monitor flags fcsfail 

sudo ifconfig phy0 up
sudo ifconfig phy1 up

sudo ifconfig phy0 mtu 1600
sudo ifconfig phy1 mtu 1600

sudo iw phy phy0 set channel 11
sudo iw phy phy1 set channel 11

sudo ifconfig mtu 400
