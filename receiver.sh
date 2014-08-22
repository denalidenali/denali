#!/usr/bin/sh
#This script runs on the client(receiver) side. 
#It creates a TUN interface and assigns subnet to it
#It then creates virtual monitor interfaces on wifi and assigns MTU
#It then sets a specific channel for receiving the frames
#
#


sudo openvpn --mktun --dev tun12
sudo ip link  set tun12 up 
sudo ip addr add 10.0.0.12/24 dev tun12 

sudo iw phy phy0 interface add phy0 type monitor flags fcsfail 
sudo iw phy phy1 interface add phy1 type monitor flags fcsfail 
#sudo iw phy phy1 interface add phy1 type monitor flags fcsfail 
sudo ifconfig phy0 up
sudo ifconfig phy1 up
#sudo ifconfig phy1 up
sudo iw phy phy0 set channel 11
sudo ifconfig phy0 mtu 1600

sudo iw phy phy1 set channel 11
sudo ifconfig phy1 mtu 1600
