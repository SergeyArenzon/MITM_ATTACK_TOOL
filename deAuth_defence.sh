#!/usr/bin/env python

from scapy.all import *

def PacketHandler( pkt ):
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0xC:
        print "Deauth packet sniffed: %s" % (pkt.summary())

sniff(iface="mon0", prn = PacketHandler)