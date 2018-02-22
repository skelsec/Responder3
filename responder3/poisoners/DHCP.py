import socket
import struct
import logging
import asyncio
import ipaddress
import traceback

from responder3.core.commons import *
from responder3.protocols.DHCP import * 
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class DHCPSession(ResponderServerSession):
	def __init__(self):
		self.sessions = {}
		self.ip_pool  = None

class DHCP(ResponderServer):
	def custom_socket(server_properties):
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		sock.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
		sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		sock.bind(('0.0.0.0', server_properties.bind_port))
		return sock

	def init(self):
		self.parser = DHCPMessage
		self.settings.ourIP = ipaddress.ip_address('192.168.1.1') #TODO: find a way to get our IP
		self.settings.IPleasetime = 199
		self.settings.offer_options = None
		self.settings.ack_options = None
		self.settings.subnetmask = 'FF:FF:FF:00'

	def get_next_ip(self):
		return IPv4Address('192.168.1.100')
		
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
			print(repr(msg))
			if msg.xid not in self.session.sessions:
				self.session.sessions[msg.xid] = msg
			else:
				self.session.sessions[msg.xid].append(msg)

			if self.session.sessions[msg.xid][-1].dhcpmessagetype == DHCPOptMessageType.DHCPDISCOVER:
				#this should be the first message for this transactionID
				if len(self.session.sessions[msg.xid]) > 1:
					raise Exception('TID collision?')

				options = [DHCPOptDHCPMESSAGETYPE.construct(DHCPOptMessageType.DHCPOFFER)]
				options.append(DHCPOptSERVERIDENTIFIER.construct(self.settings.ourIP))
				options.append(DHCPOptIPADDRESSLEASETIME.construct(self.settings.IPleasetime))
				if self.settings.offer_options is not None:
					options += self.settings.offer_options
				options.append(DHCPOptEND.construct())
				dhcpoffer = DHCPMessage.construct(self.session.sessions[msg.xid][-1].xid, DHCPOpcode.BOOTREPLY, options, yiaddr = self.get_next_ip(),
					siaddr = self.settings.ourIP, macaddress = self.session.sessions[msg.xid][-1].macaddress)
				self._soc.sendto(dhcpoffer.toBytes(), ('255.255.255.255', 67))

			elif self.session.sessions[msg.xid][-1].dhcpmessagetype == DHCPOptMessageType.DHCPREQUEST:
				if len(self.session.sessions[msg.xid]) < 1:
					raise Exception('Unseen TID with request message!')

				options = [DHCPOptDHCPMESSAGETYPE.construct(DHCPOptMessageType.DHCPACK)]
				options.append(DHCPOptSERVERIDENTIFIER.construct(self.settings.ourIP))
				options.append(DHCPOptIPADDRESSLEASETIME.construct(self.settings.IPleasetime))
				options.append(DHCPOptSUBNETMASK.construct(self.settings.subnetmask))
				if self.settings.ack_options is not None:
					options += self.settings.ack_options
				options.append(DHCPOptEND.construct())
				dhcpoffer = DHCPMessage.construct(self.session.sessions[msg.xid][-1].xid, DHCPOpcode.BOOTREPLY, options, yiaddr = IPv4Address('192.168.1.100'),
					siaddr = self.settings.ourIP, macaddress = self.session.sessions[msg.xid][-1].macaddress)
				self._soc.sendto(dhcpoffer.toBytes(), ('255.255.255.255', 67))

			else:
				print('Unknown message! %s' % repr(msg))

		except Exception as e:
			traceback.print_exc()
			self.log('Exception! %s' % (str(e),))
			pass


