import os
import ifcfg



def chooseDevice():
    devicesName = []
    for name, interface in ifcfg.interfaces().items():
        # print(interface['name'])         # First IPv4 found
        # print(interface['inet4'])        # List of ips
        # print(interface['inet6'])
        # print(interface['netmask'])
        # print(interface['broadcast'])
        devicesName.append(interface['device'])
    print("Choose attacking device: ")
    count = 1
    for device in devicesName:
        print(str(count) + '.' + device)
        count += 1

    choice = int(input());
    attDevice = devicesName[choice - 1]
    return attDevice

def APScan():
    scanDevice = chooseDevice()
    os.system("iwlist " + scanDevice + " scan")

    # os.system("sudo -S iwlist " + scanDevice + " scan")



def goMonitorMode(attDevice):
    os.system("sudo -S ifconfig " + attDevice + " down")
    os.system("sudo -S iwconfig " + attDevice + " mode monitor")
    os.system("sudo -S ifconfig " + attDevice + " up")
    print(attDevice + " is now in monitor mode!")




if __name__ == "__main__":


    APScan()


    # devicesName = []
    # for name, interface in ifcfg.interfaces().items():
    #     # print(interface['name'])         # First IPv4 found
    #     # print(interface['inet4'])        # List of ips
    #     # print(interface['inet6'])
    #     # print(interface['netmask'])
    #     # print(interface['broadcast'])
    #     devicesName.append(interface['device'])
    # print("Choose attacking device: ")
    # count = 1
    # for device in devicesName:
    #     print(str(count) + '.' + device)
    #     count += 1
    #
    # choice = int(input());
    # attDevice = devicesName[choice - 1]
    # goMonitorMode(attDevice)

