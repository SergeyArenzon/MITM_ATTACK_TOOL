import ifcfg
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.l2 import ARP, Ether
from wifi import Cell, Scheme
from scapy.all import *
from PyAccessPoint import pyaccesspoint


def chooseDevice():
    devicesName = []
    for name, interface in ifcfg.interfaces().items():
        # print(interface['name'])         # First IPv4 found
        # print(interface['inet4'])        # List of ips
        # print(interface['inet6'])
        # print(interface['netmask'])
        # print(interface['broadcast'])
        devicesName.append(interface['device'])
    print("Choose AP creating device: ")
    count = 1
    for device in devicesName:
        print(str(count) + '.' + device)
        count += 1

    choice = int(input());
    attDevice = devicesName[choice - 1]
    return attDevice


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


def checkFotRoot():
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script\n")


class AP:
    def __init__(self, wlan):
        self.wlan = wlan
        #self.ssid = ssid
        self.ap =  pyaccesspoint.AccessPoint(wlan=wlan, ssid='sergey',password="123456789")

    def start(self):
        self.ap.start()
    def stop(self):
        self.ap.stop()

def apRescanHandler(interface):
    devices = (list(printAP(interface)))
    attSsid = input("\nChoose your attack AP or \"R\" fore rescan: ")
    while attSsid == "R" or attSsid == "r":
        devices = (list(printAP(interface)))
        attSsid = input("\nChoose your attack AP or \"R\" fore rescan: ")
    return devices[int(attSsid) - 1].ssid

if __name__ == "__main__":
    checkFotRoot()
    apDevice = chooseDevice()
    ssid = apRescanHandler(apDevice)
    print(ssid)
    # print(attDevice)
    # os.system('trackerjacker -i ' + attDevice + ' --h')
    # goMonitorMode(attDevice)