import os
import sys
import socket
import struct
import asyncio
import ipaddress
import traceback


from responder3.core.commons import *
from responder3.core.udpwrapper import UDPServer
from responder3.protocols.DNS import *
from responder3.protocols.LLMNR import *


class LLMNRClient():
	def __init__(self, ipversion = 4, ifname = 'eth0', timeout = 1):
		self._mcast_ip4 = ipaddress.ip_address('224.0.0.252')
		self._mcast_ip6 = ipaddress.ip_address('FF02:0:0:0:0:0:1:3')

		self._timeout = timeout
		self._ipversion = ipversion
		self._ifname = ifname
		self._query_TIDs = []
		self._soc = None
		self._server_coro = None
		self._query_packet = None
		self._loop    = asyncio.get_event_loop()
		self.result = {}

	def setup_socket(self):
		if self._ipversion == 4:
			self._mcast_addr = (str(self._mcast_ip4), 5355)
			self._soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			self._soc.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
			self._soc.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
			self._soc.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
			self._soc.bind(('', 5355))
			mreq = struct.pack("=4sl", self._mcast_ip4.packed, socket.INADDR_ANY)
			self._soc.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

		else:
			interface_index = socket.if_nametoindex(self._ifname)
			self._soc = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			self._soc.bind(('::', 5355, 0, interface_index))
			self._soc.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
				struct.pack('16sI', self._mcast_ip6.packed, interface_index))
			self._soc.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
			self._mcast_addr = (str(self._mcast_ip6), 5355, 0, interface_index)


	def create_server(self):
		self._server = UDPServer(self.listen_responses, None, socket = self._soc)
		self._server_coro = self._server.run()

	def send_queries(self, query_names):
		qstns = []
		for qry in query_names:
			self.result[qry] = []
			tid = os.urandom(2)
			self._query_TIDs.append(tid)
			qstns.append(DNSQuestion.construct(qry, DNSType.A, DNSClass.IN))
			self._query_packet = LLMNRPacket.construct(TID = tid, 
													 response  = LLMNRResponse.REQUEST, 
													 questions = qstns)

			self._soc.sendto(self._query_packet.toBytes(), self._mcast_addr)

	@asyncio.coroutine
	def stop_loop(self):
		yield from asyncio.sleep(self._timeout)
		self._loop.stop()
		return

	def run(self, query_names):
		self.setup_socket()
		self.create_server()
		self.send_queries(query_names)

		self._loop.create_task(self.stop_loop())
		try:
			self._loop.run_until_complete(self._server_coro)
		except RuntimeError as e:
			if str(e) == 'Event loop stopped before Future completed.':
				pass
			else:
				raise(e)
		except Exception as e:
			traceback.print_exc()
			print(e)
		
		self.print_result()

	def print_result(self):
		print('NAME\tIP\t\tRESPONSE_FROM')
		for qry in self.result:
			for res in self.result[qry]:
				for src in res:
					print('%s\t%s\t%s' % (qry, res[src], src))

		
	def listen_responses(self, reader, writer):
		msg = LLMNRPacket.from_buffer(reader.buff)
		if msg.QR == LLMNRResponse.RESPONSE:
			if msg.TransactionID in self._query_TIDs:
				for ans in msg.Answers:
					if ans.TYPE == DNSType.A or ans.TYPE == DNSType.AAAA:
						self.result[ans.NAME.name].append({writer._addr[0] : str(ans.ipaddress)})
			else:
				print('[!] Got response with unknown TID!')


def main():
	import argparse
	parser = argparse.ArgumentParser(description = 'LLMNR client. Resolves a hostname using LLMNR')
	parser.add_argument("-q", action='append', help="DNS name to query")
	parser.add_argument("-6", action="store_false", dest='ipversion', help="IP version")
	parser.add_argument("-i", dest='interface', default= None, help="Interface name")
	parser.add_argument("-t", dest='timeout', default=1, help="Time to wait for responses")
	args = parser.parse_args()

	ipversion = 4 if args.ipversion else 6
	if ipversion == 6 and args.interface is None:
		print('Interface MUST be specified when using IPv6')
		sys.exit()

	client = LLMNRClient(ipversion, args.interface, args.timeout)
	client.run(args.q)

if __name__ == '__main__':
	main()