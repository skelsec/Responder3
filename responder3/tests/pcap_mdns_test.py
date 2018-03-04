
#sudo tshark -Y "udp.port == 53" -r re-01.cap -w dns.pcap
import sys
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket, Packet, SimplePacket
from scapy.layers.dot11 import Dot11
from scapy.all import *
from responder3.protocols.DNS import *
import traceback

PACKET_TYPES = EnhancedPacket, Packet, SimplePacket

#if not pkt.haslayer(UDP) or not pkt.haslayer(IP):

total = 0
parsed = 0
with open('/home/garage/Desktop/mdns.pcap','rb') as fp:
	scanner = FileScanner(fp)
	for block in scanner:
		if isinstance(block, PACKET_TYPES):
			try:
				pkt = Dot11(block.packet_data)
				if pkt.haslayer(UDP):
					total += 1
					msg = DNSPacket.from_bytes(raw(pkt[UDP].payload))
					parsed += 1
			except Exception as e:
				#traceback.print_exc()
				print(e)
				#input()

print('TOTAL: %s Parsed: %s' % (total, parsed))
