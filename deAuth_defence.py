from scapy.all import *
from scapy.layers.dot11 import Dot11


def PacketHandler( pkt ):
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0xC:
        print ("Deauth packet sniffed: %s" % (pkt.summary()))

sniff(iface="wlp3s0", prn = PacketHandler)

#
# count = 0
#
# def PacketHandler(pkt):
#     global count
# #    print "got pkt"
#     if pkt.haslayer(Dot11FCS):
#         if pkt.type == 0 and pkt.subtype == 0xc:
# 	    count = count + 1
#             print "Deauth packet sniffed: %d" % (count)
#     if count >= 20:
#         print "warning you'r AP is under deauthattack -- could lead to Evil_Twin attack or to Rouge AP call the police for more info"
#
# sniff(iface="wlan1", prn = PacketHandler)