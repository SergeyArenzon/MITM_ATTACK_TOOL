import os
import ifcfg
import json

if __name__ == "__main__":
    ifconfig = os.system("ifconfig")
    print(ifconfig)
    print('-----------------------------------------------------')
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
    print(devicesName[choice - 1])
