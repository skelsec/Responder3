import os
import random
import socket
import struct
import logging
import asyncio
import ipaddress
import traceback

from responder3.core.commons import *
from responder3.protocols.DHCP import * 
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

class DHCPResult():
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

class DHCPGlobalSession():
	def __init__(self, server_properties):
		self.server_properties = server_properties
		self.settings = server_properties.settings
		self.sessions = {}
		self.assigned_ips = {} #xid - ip
		self.offer_mac = {}
		self.ip_pool  = None #ipaddress.IPv4Network

		self.parse_settings()

	def parse_settings(self):
		#default values
		#defaults
		self.serveraddress = self.server_properties.bind_addr
		self.subnetmask    = 'FF:FF:FF:00'
		self.leasetime     = random.randint(600,1000)
		self.offer_options = None
		self.ack_options   = None
		self.poisonermode = PoisonerMode.ANALYSE

		start = ipaddress.IPv4Address('192.168.1.100')
		end = ipaddress.IPv4Address('192.168.1.200')
		ipnet  = ipaddress.summarize_address_range(start, end)

		if 'ip_pool' in self.settings:
			#expected format: 192.168.1.100-200
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
			self.log(logging.INFO, 'No settings defined, adjusting to Analysis functionality!')
			self.poisonermode = PoisonerMode.ANALYSE
		
		else:
			if 'mode' in self.settings:
				self.poisonermode = self.settings['mode']
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
	pass

class DHCP(ResponderServer):
	def custom_socket(server_properties):
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		sock.setblocking(False)#SUPER IMPORTANT TO SET THIS FOR ASYNCIO!!!!
		sock.setsockopt(socket.SOL_SOCKET, 25, server_properties.bind_iface.encode())
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,1)
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		sock.bind(('0.0.0.0', server_properties.bind_port)) #only IPv4 is supported, because IPv6 packs it's own DHCP protocol, which is completely different
		return sock

	def init(self):
		self.parser = DHCPMessage
		
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
				print(msg.dhcpmessagetype)
				#we only will see ACKs broadcasted from server to client
				if msg.dhcpmessagetype == DHCPOptMessageType.DHCPACK:
					result = DHCPResult.from_dhcpmessage(msg)
					print(str(result))
					return

			else:
				print(msg)
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

					print('Sending offer!')
					yield from self.send_data(dhcpoffer.toBytes()[:300], ('255.255.255.255', 68))

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

						print('Sending ACK to %s' % str(self.globalsession.assigned_ips[msg.xid]))
						#yield from self.send_data(dhcpack.toBytes(), ('255.255.255.255', 68))
						

						if self.globalsession.sessions[msg.xid][-1].flags & DHCPFlags.B == 0 and self.cwriter._addr[0] != '0.0.0.0':
							yield from self.send_data(dhcpack.toBytes(), (str(self.globalsession.assigned_ips[msg.xid]), 68))
						else:
							yield from self.send_data(dhcpack.toBytes(), ('255.255.255.255', 68))
						

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
						
						yield from self.send_data(dhcpnak.toBytes(), ('255.255.255.255', 68))



				else:
					pass
					#print('Unknown message! %s' % repr(msg))

		except Exception as e:
			traceback.print_exc()
			self.log('Exception! %s' % (str(e),))
			pass


