#!/usr/bin`
# /env python3
from typing import Type, List, Any, Union

from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Packet
import sys
import yaml
from scapy.plist import PacketList

with open(sys.argv[1]) as file:
	config = yaml.load(file, Loader=yaml.FullLoader)

ip_frag_schema: str
if 'pcap_path' in config:
	FILE = rdpcap(config['pcap_path'])
if 'ipv4_fragment_reassembly' in config:
	ip_frag_schema = config['ipv4_fragment_reassembly']


def snitch(target: Packet):
	timestamp = int(target.time)
	s_mac = target[Ether].src
	s_ip = 'null'
	s_port = 'null'

	t_mac = target[Ether].dst
	t_ip = 'null'
	t_port = 'null'

	attack = 'silly string'

	if IP in target:
		s_ip = target[IP].src
		t_ip = target[IP].dst
	if ARP in target:
		attack = "arp_cache_poisoning"
	elif ICMP in target:
		attack = "oversize_ipv4_fragments"

	print("---\n" +
		  "timestamp: " + str(timestamp) + "\n" +
		  "source:\n" +
		  "  mac_address: " + str(s_mac) + "\n" +
		  "  ipv4_address: " + str(s_ip) + "\n" +
		  "  tcp_port: " + str(s_port) + "\n" +
		  "target:\n" +
		  "  mac_address: " + str(t_mac) + "\n" +
		  "  ipv4_address: " + str(t_ip) + "\n" +
		  "  tcp_port: " + str(t_port) + "\n" +
		  "attack: " + attack)


# tracks all ARPs
# key: IP, Value: MAC address
arp_table = dict()


# Checks a given sniffed ARP packet for ARP Poisoning behavior
def poison_detector(target: Packet):
	ip = target[ARP].psrc
	mac = target[ARP].hwsrc
	# Checks if the given packet is reporting a new MAC address for a previously established IP
	if ip in arp_table:
		if arp_table[ip] != mac:
			snitch(target)  # snitches if Key:Value doesn't match

	else:
		arp_table[ip] = mac


# Checks ICMP pings for PoD packet sizes
def pod_detector(target: Packet, session: PacketList, sesh_ip: PacketList):
	# check for packets that advertise a total size greater than 65,535
	# total_size = target[IP].frag * 8 + target[IP].len
	ping_size: int = 0
	for datum in session:
		ping_size += datum[IP].len - (datum[IP].ihl * 4)

	for datum in sesh_ip:
		ping_size += datum[IP].len - (datum[IP].ihl * 4)
	#snitches if the packet exceeds the ping of death
	if 65535 <= ping_size:
		snitch(target)




def main():
	# sniffs packets and sorts them like the Willy Wonka Geese
	egg: Packet
	convos = FILE.sessions()
	for egg in FILE:
		if ARP in egg:
			poison_detector(egg)
		elif ICMP in egg:
			if egg[ICMP].type == 0:
				key_ping = ("ICMP " + str(egg[IP].src) + " > " + str(egg[IP].dst) + " type=" + str(
					egg[ICMP].type) + " code=" + str(egg[ICMP].code) + " id=" + str(hex(egg[ICMP].id)))
				key_ip = ("IP " + str(egg[IP].src) + " > " + str(egg[IP].dst) + " proto=icmp")
				pod_detector(egg, convos.get(key_ping), convos.get(key_ip))


# calls different functions for different packet types


if __name__ == "__main__":
	main()
