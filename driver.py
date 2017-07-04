#!/usr/bin/env python
import os
import pyx
import logging
import subprocess	
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

ap_list = []
def PacketHandler(pkt):
	#pktss.add(pkt.summary)
	#print(pkt.info)
	#print('hi')
	#if pkt.haslayer(Dot11) :
	#if pkt.type == 4 and pkt.subtype == 8 :
	#if pkt.addr2 not in ap_list :
	#ap_list.append(pkt.addr2)
	#print('hi')
	#wrpcap("ok.pcap",pktss)
	#print('AP MAC: {0} with SSID: {1} and type is {2}'.format(pkt.addr2, pkt.info,pkt.type))
	print(pkt.summary)
	
# already concurrent with shell=True
#try:
	#subprocess.call("ping pornhub.com" , shell=True,timeout=3)	
#except subprocess.TimeoutExpired:
	#print('ending')

print('\n---------------summary------------------')	
pkts=sniff(count=5 , iface="mon0", prn = PacketHandler)
print(pkts[0].getlayer(ICMP))

# ----------------------------keep running in some loop(GOTTA CHECK) 
#pkts.pdfdump("some.pdf")
wrpcap("ok2.pcap",pkts)	