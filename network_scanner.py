#! /usr/bin/env python

import scapy.all as scapy
import socket

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        print(element[1].psrc)
        hostname = ''
        try:
            hostname = socket.gethostbyname_ex(element[1].psrc)
        except Exception:
            print("seila")
        print(hostname)
        clients_list.append({"ip": element[1].psrc, "mac":element[1].hwsrc})

    return clients_list


def print_list(list):
    print("IP\t\t\tMAC Address\n-------------------------------------------")
    for element in list:
        print(element["ip"] + "\t\t" + element["mac"])


list = scan("10.0.2.1/24")
print_list(list)