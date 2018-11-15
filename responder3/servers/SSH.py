#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
# Module to grab SSH credentials

import logging
import asyncio


from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.SSH import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

#

class SSHSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.cipher = SSHCipher()
		self.state = 'BANNER'
		self.client_banner = None
		self.server_banner = 'SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2'
		self.client_kxinit = None
		self.server_kxinit = None
		self.parser = SSHParser

	def __repr__(self):
		t  = '== SSHSession ==\r\n'
		return t


class SSH(ResponderServer):
	def init(self):
		self.parse_settings()
		
	def parse_settings(self):
		pass

	async def banner_exchange(self, timeout=1):
		try:
			#read client banner
			client_banner = await readline_or_exc(self.creader, timeout=timeout)
			self.session.client_banner = client_banner.decode().strip()
			print(self.session.client_banner)
			
			#send server banner
			self.cwriter.write(self.session.server_banner.encode()+b'\r\n')
			await self.cwriter.drain()
			
			return 'OK'
			
		except Exception as e:
			print(e)
			return 'NO'
			
	async def key_exchange(self, msg, timeout = 1):
		try:
			self.session.client_kxinit = msg.payload.raw
			packet = SSHPacket()
			packet.payload = self.session.cipher.generate_server_key_rply()
			packet_data = packet.to_bytes()
			self.session.server_kxinit = packet.payload.to_bytes()
			
			print('resp')
			self.cwriter.write(packet_data)
			await self.cwriter.drain()
			
			print('getting resp')
			msg = await asyncio.wait_for(self.parse_message(), timeout = 2)
			print(str(msg))
			
			payload = self.session.cipher.calculate_kex(self.session.client_banner.encode(), self.session.server_banner.encode(), self.session.client_kxinit, self.session.server_kxinit, msg.payload)
			
			packet = SSHPacket()
			packet.payload = payload
			
			print('resp')
			self.cwriter.write(packet.to_bytes())
			await self.cwriter.drain()
			
		except Exception as e:
			traceback.print_exc()
		
	@r3trafficlogexception
	async def run(self):
		while not self.shutdown_evt.is_set():
			if self.session.state == 'BANNER':
				status = await self.banner_exchange()
				if status == 'OK':
					self.session.state = 'KEX'
					continue
				raise Exception('Banned exchange failed!')
					
			msg = await asyncio.wait_for(self.parse_message(), timeout = 2)
			print(str(msg))
					
			if self.session.state == 'KEX':
				print('KEX')
				await self.key_exchange(msg)
				return
				