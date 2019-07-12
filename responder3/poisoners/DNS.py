import re
import socket
import logging
import asyncio
import traceback
import ipaddress
import datetime
import collections

from responder3.core.interfaces.NetworkInterfaces import interfaces
from responder3.core.commons import PoisonerMode
from responder3.protocols.DNS import * 
from responder3.core.udpwrapper import UDPClient
from responder3.core.servertemplate import ResponderServer, ResponderServerSession, ResponderServerGlobalSession


class DNSGlobalSession():
	def __init__(self, listener_socket_config, settings, log_queue):
		ResponderServerGlobalSession.__init__(self, log_queue, self.__class__.__name__)
		self.listener_socket_config = listener_socket_config
		self.settings = settings
		self.spooftable = collections.OrderedDict()
		self.poisonermode = PoisonerMode.ANALYSE
		self.passthru = True
		self.passthru_iface = None
		self.passthru_iface_idx = None
		self.passthru_proto = None
		self.passthru_ip = None

		self.parse_settings()

	def parse_settings(self):
		self.passthru = False
		if 'passthru' in self.settings and self.settings['passthru']:
			self.passthru = True
			marker = self.settings['passthru']['dnsserver'].rfind(':')
			if marker != -1:
				self.passthru_server = ipaddress.ip_address(self.settings['passthru']['dnsserver'][:marker])
				self.passthru_port = int(self.settings['passthru']['dnsserver'][marker+1:])
			
			else:
				self.passthru_server = ipaddress.ip_address(self.settings['passthru']['dnsserver'])
				self.passthru_port   = 53
			
			self.passthru_iface  = self.settings['passthru']['bind_iface'] if 'bind_iface' in self.settings['passthru'] else self.listener_socket_config.bind_iface
			self.passthru_iface_idx = self.listener_socket_config.bind_iface_idx
			self.passthru_proto  = self.settings['passthru']['bind_protocol'] if 'bind_protocol' in self.settings['passthru'] else self.listener_socket_config.bind_protocol
			self.passthru_ip     = ipaddress.ip_address(self.settings['passthru']['bind_addr']) if 'bind_addr' in self.settings['passthru'] else None

			if self.passthru_ip is None and self.passthru_iface != self.listener_socket_config.bind_iface:
				self.passthru_ip = interfaces.get_ip(self.passthru_iface, self.passthru_server.version)[0]
			else:
				self.passthru_ip = self.listener_socket_config.bind_addr

		if self.settings is None:
			self.log('No settings defined, adjusting to Analysis functionality!')

		else:
			# parse the poisoner mode
			if isinstance(self.settings['mode'], str):
				self.poisonermode = PoisonerMode[self.settings['mode'].upper()]

			# compiling re strings to actual re objects and converting IP strings to IP objects
			if self.poisonermode == PoisonerMode.SPOOF:
				for entry in self.settings['spooftable']:
					for regx in entry:
						self.spooftable[re.compile(regx)] = ipaddress.ip_address(entry[regx])

class DNSSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)


class DNS(ResponderServer):
	def init(self):
		self.parser = DNSPacket

	async def parse_message(self):
		msg = await asyncio.wait_for(self.parser.from_streamreader(self.creader, self.globalsession.listener_socket_config.bind_protocol), timeout = 1)
		return msg

	async def send_data(self, data, addr = None):
		if self.listener_socket_config.bind_protocol == socket.SOCK_DGRAM:
			self.cwriter.write(data)
			#await asyncio.wait_for(self.cwriter.write(data, addr), timeout=1)
		else:
			self.cwriter.write(data)
			await self.cwriter.drain()
		return

	async def poll_dnsserver(self, msg):
		await self.log('Polling passthru server at %s!' % (str(self.globalsession.passthru_server),))
		if self.globalsession.passthru_proto == socket.SOCK_DGRAM:
			if self.globalsession.passthru_ip.version == 4:
				sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
				sock.setblocking(False)
				sock.setsockopt(socket.SOL_SOCKET, 25, self.globalsession.passthru_iface.encode())
				sock.bind((str(self.globalsession.passthru_ip), 0))
			
			else:
				sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
				sock.setblocking(False)
				sock.setsockopt(socket.SOL_SOCKET, 25, self.globalsession.passthru_iface.encode())
				sock.bind((str(self.globalsession.passthru_ip), 0, self.globalsession.passthru_iface_idx ))

			client = UDPClient((str(self.globalsession.passthru_server), self.globalsession.passthru_port), sock = sock)
			reader, writer = await asyncio.wait_for(client.run(msg.to_bytes()), timeout = 1)

		else:
			if self.globalsession.passthru_ip.version == 4:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
				sock.setsockopt(socket.SOL_SOCKET, 25, self.globalsession.passthru_iface.encode())
				sock.bind((str(self.globalsession.passthru_ip), 0))
				sock.connect((str(self.globalsession.passthru_server), self.globalsession.passthru_port))

			else:
				sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_TCP)
				sock.setblocking(False)
				sock.setsockopt(socket.SOL_SOCKET, 25, self.globalsession.passthru_iface.encode())
				sock.bind((str(self.globalsession.passthru_ip), 0, self.globalsession.passthru_iface_idx ))
				sock.connect((str(self.globalsession.passthru_server), self.globalsession.passthru_port))
			
			reader, writer = await asyncio.wait_for(asyncio.open_connection(sock = sock), timeout = 1)
		
			writer.write(msg.to_bytes())
			await writer.drain()
		
		passthru_packet = await asyncio.wait_for(DNSPacket.from_streamreader(reader, self.globalsession.passthru_proto), timeout = 1)
		await self.log('Passthru packet recieved!')
		return passthru_packet

	async def run(self):
		try:
			msg = await asyncio.wait_for(self.parse_message(), timeout=1)
			if self.globalsession.poisonermode == PoisonerMode.ANALYSE:
				for q in msg.Questions:
					await self.logger.poisonresult(self.globalsession.poisonermode, requestName = q.QNAME.name, request_type = q.QTYPE.name)

			else:
				answers = []
				for q in msg.Questions:
					for spoof_regx in self.globalsession.spooftable:
						spoof_ip = self.globalsession.spooftable[spoof_regx]
						if spoof_regx.match(q.QNAME.name):
							res = None
							await self.logger.poisonresult(self.globalsession.poisonermode, requestName = q.QNAME.name, poisonName = str(spoof_regx), poisonIP = spoof_ip, request_type = q.QTYPE.name)
							if spoof_ip.version == 4 and q.QTYPE == DNSType.A:
								res = DNSAResource.construct(q.QNAME.name, spoof_ip)
							elif spoof_ip.version == 6 and q.QTYPE == DNSType.AAAA:
								res = DNSAAAAResource.construct(q.QNAME.name, spoof_ip)
							
							if res:
								answers.append(res)
							break

						elif self.globalsession.passthru:
							await self.logger.poisonresult(PoisonerMode.ANALYSE, requestName = q.QNAME.name, request_type = q.QTYPE.name)
							#if ANY of the query names requested doesnt match our spoof table, then we ask an actual DNS server
							#this completely overrides any match from the spooftable!
							passthru_ans = await asyncio.wait_for(self.poll_dnsserver(msg), timeout=1)
							#modify response here!
							passthru_ans_modified = passthru_ans
							#print(passthru_ans_modified)
							await asyncio.wait_for(self.send_data(passthru_ans_modified.to_bytes()), timeout=1)
							return
						
						else:
							await self.logger.poisonresult(PoisonerMode.ANALYSE, requestName = q.QNAME.name, request_type = q.QTYPE.name)

				if len(answers) == 0 :
					#DNS error response should be here!
					#raise Exception('DNS error response should be here!')
					return

				response = DNSPacket.construct(TID = msg.TransactionID, 
												 response = DNSResponse.RESPONSE, 
												 answers = answers,
												 questions = msg.Questions,
												 proto = self.listener_socket_config.bind_protocol)
			
				await asyncio.wait_for(self.send_data(response.to_bytes()), timeout=1)

		except Exception as e:
			raise e