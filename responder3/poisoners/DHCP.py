import os
import random
import socket
import struct
import logging
import asyncio
import ipaddress
import traceback

from responder3.core.sockets import setup_base_socket
from responder3.core.commons import PoisonerMode
from responder3.protocols.DHCP import * 
from responder3.core.servertemplate import ResponderServer, ResponderServerSession, ResponderServerGlobalSession

class DHCPResult:
	def __init__(self):
		self.offered_ip = None
		self.dhcp_server_ip = None
		self.client_mac = None
		self.options = None

	def from_dhcpmessage(msg):
		res = DHCPResult()
		res.offered_ip = msg.yiaddr
		res.dhcp_server_ip = msg.siaddr
		res.client_mac = msg.chaddr
		res.options = msg.options
		return res

	def __repr__(self):
		t = 'DHCP server on address %s offered an IP %s to the client with MAC address of %s' % (self.dhcp_server_ip, self.offered_ip, self.client_mac)
		return t

	def __str__(self):
		return repr(self)


class DHCPGlobalSession(ResponderServerGlobalSession):
	def __init__(self, listener_socket_config, settings, log_queue):
		ResponderServerGlobalSession.__init__(self, log_queue, self.__class__.__name__)
		self.listener_socket_config = listener_socket_config
		self.settings = settings
		self.sessions = {}
		self.assigned_ips = {} #xid - ip
		self.offer_mac = {}
		self.ip_pool  = None #ipaddress.IPv4Network

		self.parse_settings()

	def parse_settings(self):
		#default values
		#defaults
		self.serveraddress = self.listener_socket_config.bind_addr
		self.subnetmask    = 'FF:FF:FF:00'
		self.leasetime     = random.randint(600,1000)
		self.offer_options = None
		self.ack_options   = None
		self.ip_pool = None
		self.poisonermode = PoisonerMode.ANALYSE

		start = ipaddress.IPv4Address('192.168.1.100')
		end = ipaddress.IPv4Address('192.168.1.200')
		ipnet  = ipaddress.summarize_address_range(start, end)

		if 'ip_pool' in self.settings:
			# expected format: 192.168.1.100-200
			start = ipaddress.IPv4Address(self.settings['ip_pool'].split('-')[0].strip())
			m = self.settings['ip_pool'].rfind('.')
			end   = ipaddress.IPv4Address(self.settings['ip_pool'][:m+1] + self.settings['ip_pool'].split('-')[1].strip())
			ipnets = ipaddress.summarize_address_range(start, end)

			ips = []
			for ipnet in ipnets:
				for ip in ipnet:
					ips.append(ip)

			self.ip_pool = iter(ips)


		if self.settings is None:
			self.log('No settings defined, adjusting to Analysis functionality!')
			self.poisonermode = PoisonerMode.ANALYSE
		
		else:
			if 'mode' in self.settings:
				self.poisonermode = PoisonerMode(self.settings['mode'].upper())
			if 'subnetmask' in self.settings:
				self.subnetmask = self.settings['subnetmask']
			if 'leasetime' in self.settings:
				self.leasetime = self.settings['leasetime']
			if 'offer_options' in self.settings:
				if not isinstance(self.settings['offer_options'], list):
					raise Exception('A list of touples is expected for DHCPoptions')
				self.offer_options = []
				
				for code, data in self.settings['offer_options']:
					self.offer_options.append(OPTCode2ClassName[int(code)].from_setting(data))
			
			if 'ack_options' in self.settings:
				if not isinstance(self.settings['ack_options'], list):
					raise Exception('A list of touples is expected for DHCPoptions')
				self.ack_options = []
				
				for code, data in self.settings['ack_options']:
					self.ack_options.append(OPTCode2ClassName[int(code)].from_setting(data))


class DHCPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)


class DHCP(ResponderServer):
	@staticmethod
	def custom_socket(socket_config):
		if socket_config.bind_family == 6:
			raise Exception('DHCP server should not be run on IPv6 (requires a different protocol)')
		sock = setup_base_socket(socket_config)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0) #important to turn off reuse address (at least on windows!!!)
		return sock

	def init(self):
		self.parser = DHCPMessage
		
	async def parse_message(self):
		msg = await asyncio.wait_for(self.parser.from_streamreader(self.creader), timeout=1)
		return msg

	async def send_data(self, data, addr = None):
		await asyncio.wait_for(self.cwriter.write(data), timeout=1)
		return
		
	async def send_broadcast(self, data, addr):
		self.cwriter.write_broadcast(data, addr)
		return

	async def run(self):
		try:
			msg = await asyncio.wait_for(self.parse_message(), timeout=1)
			if self.globalsession.poisonermode == PoisonerMode.ANALYSE:
				for opt in msg.options:
						if isinstance(opt, DHCPOptHOSTNAME) == True:
							await self.log('DHCP device hostname: %s' % opt.hostname)

				if msg.dhcpmessagetype == DHCPOptMessageType.DHCPACK:
					result = DHCPResult.from_dhcpmessage(msg)
					await self.log(str(result))
					return

			else:
				if msg.xid not in self.globalsession.sessions:
					self.globalsession.sessions[msg.xid] = []
				
				self.globalsession.sessions[msg.xid].append(msg)

				if self.globalsession.sessions[msg.xid][-1].dhcpmessagetype == DHCPOptMessageType.DHCPDISCOVER:
					#if self.globalsession.sessions[msg.xid][-1].chaddr in self.globalsession.offer_mac:
					#	return
					#this should be the first message for this transactionID
					#if len(self.globalsession.sessions[msg.xid]) > 2:
					#	raise Exception('TID collision?')

					options = []
					options.append(DHCPOptDHCPMESSAGETYPE.construct(DHCPOptMessageType.DHCPOFFER))
					options.append(DHCPOptSERVERIDENTIFIER.construct(self.globalsession.serveraddress))
					options.append(DHCPOptIPADDRESSLEASETIME.construct(self.globalsession.leasetime))
					options.append(DHCPOptRENEVALTIME.construct(60))
					options.append(DHCPOptREBINDINGTIME.construct(60))
					options.append(DHCPOptSUBNETMASK.construct(self.globalsession.subnetmask))
					options.append(DHCPOptROUTERS.construct(self.globalsession.serveraddress))
					options.append(DHCPOptDNSSERVERS.construct(self.globalsession.serveraddress))
					if self.globalsession.offer_options is not None:
						options += self.globalsession.offer_options
					options.append(DHCPOptEND.construct())
					offered_ip = None
					if msg.xid in self.globalsession.assigned_ips:
						offered_ip = self.globalsession.assigned_ips[msg.xid]
					else:
						offered_ip = next(self.globalsession.ip_pool)
					dhcpoffer  = DHCPMessage.construct(self.globalsession.sessions[msg.xid][-1].xid, 
						DHCPOpcode.BOOTREPLY, 
						options, 
						yiaddr = offered_ip,
						siaddr = self.globalsession.serveraddress, 
						macaddress = self.globalsession.sessions[msg.xid][-1].chaddr, 
						flags = self.globalsession.sessions[msg.xid][-1].flags,
						secs =self.globalsession.sessions[msg.xid][-1].secs)

					self.globalsession.assigned_ips[msg.xid] = offered_ip
					self.globalsession.offer_mac[self.globalsession.sessions[msg.xid][-1].chaddr] = 0

					await self.send_broadcast(dhcpoffer.to_bytes()[:300], ('255.255.255.255', 68))

				elif self.globalsession.sessions[msg.xid][-1].dhcpmessagetype == DHCPOptMessageType.DHCPREQUEST:

					if msg.xid in self.globalsession.assigned_ips:
						#ip offer already sent via DHCPOFFER
						options = []
						options.append(DHCPOptDHCPMESSAGETYPE.construct(DHCPOptMessageType.DHCPACK))
						options.append(DHCPOptSERVERIDENTIFIER.construct(self.globalsession.serveraddress))
						options.append(DHCPOptIPADDRESSLEASETIME.construct(self.globalsession.leasetime))
						options.append(DHCPOptSUBNETMASK.construct(self.globalsession.subnetmask))
						if self.globalsession.ack_options is not None:
							options += self.globalsession.ack_options
						options.append(DHCPOptEND.construct())
						dhcpack = DHCPMessage.construct(
							self.globalsession.sessions[msg.xid][-1].xid, 
							DHCPOpcode.BOOTREPLY, 
							options, 
							yiaddr = self.globalsession.assigned_ips[msg.xid],
							siaddr = self.globalsession.serveraddress, 
							macaddress = self.globalsession.sessions[msg.xid][-1].chaddr)

						await self.logger.info('Sending ACK to %s' % str(self.globalsession.assigned_ips[msg.xid]))

						if self.globalsession.sessions[msg.xid][-1].flags & DHCPFlags.B == 0 and self.cwriter.peer_address[0] != '0.0.0.0':
							await self.send_data(dhcpack.to_bytes(), (str(self.globalsession.assigned_ips[msg.xid]), 68))
						else:
							await self.send_broadcast(dhcpack.to_bytes(), ('255.255.255.255', 68))
						

					else:
						#a client tries to renew his already existing IP
						requested_ip = None
						for option in msg.options:
							if option.code == 50:
								requested_ip = option.address
						
						if requested_ip is None:
							#giving up here
							return

						print('NAK-ing client-requested IP %s' % requested_ip)

						options = [DHCPOptDHCPMESSAGETYPE.construct(DHCPOptMessageType.DHCPNAK)]
						options.append(DHCPOptEND.construct())
						dhcpnak = DHCPMessage.construct(
							self.globalsession.sessions[msg.xid][-1].xid, 
							DHCPOpcode.BOOTREPLY, 
							options, 
							siaddr = self.globalsession.serveraddress, 
							macaddress = self.globalsession.sessions[msg.xid][-1].chaddr)
						
						await self.send_broadcast(dhcpnak.to_bytes(), ('255.255.255.255', 68))



				else:
					pass
					#print('Unknown message! %s' % repr(msg))

		except Exception as e:
			raise e


