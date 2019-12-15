#!/usr/bin/env python3

import scapy.all as scapy
import argparse


def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for elemant in answered_list:
        client_dict = {"ip": elemant[1].psrc, "mac": elemant[1].hwsrc}
        clients_list.append(client_dict)
        
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMac Address\n----------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_argument()
scan_result = scan(options.target)
print_result(scan_result)