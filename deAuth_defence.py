from scapy.all import *
from scapy.layers.dot11 import Dot11


def PacketHandler( pkt ):
    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0xC:
        print ("Deauth packet sniffed: %s" % (pkt.summary()))


if __name__ == "__main__":
    sniff(iface="wlp3s0", prn = PacketHandler)