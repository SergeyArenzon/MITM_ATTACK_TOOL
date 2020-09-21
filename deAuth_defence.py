from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth


def PacketHandler( pkt ):
    deAuth_pkt_count = 0
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0xC:
        deAuth_pkt_count += 1
        if(deAuth_pkt_count >= 20):
            print("YOU'R DEVICE IS UNDER ATTACK!!")

sniff(iface="wlp0s20f0u1", prn = PacketHandler)


