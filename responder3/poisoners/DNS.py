import re
import socket
import logging
import asyncio
import traceback
import ipaddress
import datetime

from responder3.core.commons import *
from responder3.protocols.DNS import * 
from responder3.core.udpwrapper import UDPClient
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class DNSGlobalSession():
	def __init__(self, server_properties):
		self.server_properties = server_properties
		self.settings = server_properties.settings
		self.spooftable = []
		self.poisonermode = PoisonerMode.ANALYSE

		self.parse_settings()

	def parse_settings(self):
		self.passthru = False
		if 'passthru' in self.settings and self.settings['passthru']:
			self.passthru = True
			if self.settings['passthru']['dnsserver'].find(':'):
				self.passthru_server, self.passthru_port = self.settings['passthru']['dnsserver'].split(':')
				self.passthru_port = int(self.passthru_port)
			
			else:
				self.passthru_server = self.settings['passthru']['dnsserver']
				self.passthru_port   = 53
			
			self.passthru_iface  = self.settings['passthru']['bind_iface'] if 'bind_iface' in self.settings['passthru'] else self.server_properties.bind_iface
			self.passthru_proto  = self.settings['passthru']['bind_porotcol'] if 'bind_porotcol' in self.settings['passthru'] else self.server_properties.bind_porotcol
			self.passthru_ip     = self.settings['passthru']['bind_addr'] if 'bind_addr' in self.settings['passthru'] else None

			if self.passthru_ip is None and self.passthru_iface != self.server_properties.bind_iface:
				iface = self.server_properties.interfaced[self.passthru_iface]
				#grabbinf the first one!
				if ipaddress.ip_address(self.passthru_server).version == 4:
					self.passthru_ip = iface.IPv4[0]
				else:
					self.passthru_ip = iface.IPv6[0]
				



		if self.settings is None:
			self.log('No settings defined, adjusting to Analysis functionality!')

		else:
			#parse the poisoner mode
			if isinstance(self.settings['mode'], str):
				self.poisonermode = PoisonerMode[self.settings['mode'].upper()]

			#compiling re strings to actual re objects and converting IP strings to IP objects
			if self.poisonermode == PoisonerMode.SPOOF:
				for exp in self.settings['spooftable']:
					if exp == 'ALL':
						self.spooftable.append((re.compile('.*'),ipaddress.ip_address(self.settings['spooftable'][exp])))
						continue
					self.spooftable.append((re.compile(exp),ipaddress.ip_address(self.settings['spooftable'][exp])))

class DNSSession(ResponderServerSession):
	pass


class DNS(ResponderServer):
	def init(self):
		self.parser = DNSPacket

	@asyncio.coroutine
	def parse_message(self):
		return self.parser.from_buffer(self.creader.buff)

	@asyncio.coroutine
	def send_data(self, data):
		yield from asyncio.wait_for(self.cwriter.write(data), timeout=1)
		return

	@asyncio.coroutine
	def poll_dnsserver(self, msg):
		if self.globalsession.passthru_proto == ServerProtocol.UDP:
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			sock.setblocking(False)
			sock.setsockopt(socket.SOL_SOCKET, 25, self.globalsession.passthru_iface.encode())
			sock.bind((str(self.globalsession.passthru_ip), 0))
			client = UDPClient((self.globalsession.passthru_server, self.globalsession.passthru_port), sock = sock)
			reader, writer = yield from asyncio.wait_for(client.run(msg.toBytes()), timeout = 1)

		else:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
			sock.setsockopt(socket.SOL_SOCKET, 25, self.globalsession.passthru_iface.encode())
			sock.bind((str(self.globalsession.passthru_ip), 0))
			reader, writer = yield from asyncio.wait_for(asyncio.open_connection(host=self.globalsession.passthru_server, port=self.globalsession.passthru_port, sock = sock), timeout = 1)
		
			writer.write(msg.toBytes())
			yield from writer.drain()
		
		passthru_packet = yield from asyncio.wait_for(DNSPacket.from_streamreader(reader, self.globalsession.passthru_proto), timeout = 1)
		self.log(logging.INFO,'Passthru packet recieved! %s' % (repr(passthru_packet),))
		return passthru_packet

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
							#res.construct(q.QNAME, NBRType.NB, ip)
							answers.append(res)

						elif self.globalsession.passthru:
							#if ANY of the query names requested doesnt match our spoof table, then we ask an actual DNS server
							#this completely overrides any match from the spooftable!
							passthru_ans = yield from asyncio.wait_for(self.poll_dnsserver(msg), timeout=1)
							#modify response here!
							passthru_ans_modified = passthru_ans
							print(passthru_ans_modified)
							yield from asyncio.wait_for(self.send_data(passthru_ans_modified.toBytes()), timeout=1)
							return

				if len(answers) == 0 :
					#DNS error response should be here!
					#raise Exception('DNS error response should be here!')
					return

				response = DNSPacket.construct(TID = msg.TransactionID, 
												 response = DNSResponse.RESPONSE, 
												 answers = answers,
												 questions = msg.Questions,
												 proto = self.globalsession.passthru_proto)
			
				yield from asyncio.wait_for(self.send_data(response.toBytes()), timeout=1)

		except Exception as e:
			traceback.print_exc()
			self.log('Exception! %s' % (str(e),))
			pass