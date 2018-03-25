import socket
import dpkt
import sys
pcapReader = dpkt.pcap.Reader(open('/home/garage/Desktop/dns.pcap', "rb"))
for ts, data in pcapReader:
	try:
		ether = dpkt.ethernet.Ethernet(data)
		if ether.type != dpkt.ethernet.ETH_TYPE_IP: continue
		ip = ether.data
		src = socket.inet_ntoa(ip.src)
		dst = socket.inet_ntoa(ip.dst)
		print("%s -> %s" % (src, dst))
	except Exception as e:
		print(str(e))
		pass