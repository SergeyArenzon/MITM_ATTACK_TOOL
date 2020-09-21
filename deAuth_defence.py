from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth


# Sniffing for deauth pkts with monitor mode
def PacketHandler( pkt ):
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0xC:
        print("deAuth packet sniffed: " + pkt.summary())

sniff(iface="wlp0s20f0u1", prn = PacketHandler, count = 50)
print("         \033[91m======================================")
print("         \033[91m======================================")

print("         \033[91m==  YOUR ROUTER IS UNDER ATTACK!!!  ==")
print("         \033[91m======================================")
print("         \033[91m======================================")



