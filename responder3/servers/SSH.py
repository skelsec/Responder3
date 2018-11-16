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
		self.cipher = None
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
			cipher = SSHCipher()
			self.session.client_kxinit = msg.payload.raw
			packet = SSHPacket()
			packet.payload = cipher.generate_server_key_rply()
			packet_data = packet.to_bytes()
			self.session.server_kxinit = packet.payload.to_bytes()
			
			print('resp')
			self.cwriter.write(packet_data)
			await self.cwriter.drain()
			
			print('getting resp')
			msg = await asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout = 20)
			print(str(msg))
			
			payload = cipher.calculate_kex(self.session.client_banner.encode(), self.session.server_banner.encode(), self.session.client_kxinit, self.session.server_kxinit, msg.payload)
			
			packet = SSHPacket()
			packet.payload = payload
			
			print('resp')
			self.cwriter.write(packet.to_bytes())
			await self.cwriter.drain()

			packet = SSHPacket()
			packet.payload = SSH_MSG_NEWKEYS()
			self.cwriter.write(packet.to_bytes())
			await self.cwriter.drain()
			
			return cipher
			
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
				raise Exception('Banner exchange failed!')

			try:
				result = await asyncio.gather(*[asyncio.wait_for(self.session.parser.from_streamreader(self.creader, cipher = self.session.cipher), timeout=None)], return_exceptions=True)
			except asyncio.CancelledError as e:
				raise e
			if isinstance(result[0], R3ConnectionClosed):
				return
			elif isinstance(result[0], Exception):
				raise result[0]
			else:
				msg = result[0]
					
			print(str(msg))
					
			if self.session.state == 'KEX':
				print('KEX')
				cipher = await self.key_exchange(msg)
				self.session.state = 'EXPECT_NEWKEYS'
				continue

			elif self.session.state == 'EXPECT_NEWKEYS':
				if not isinstance(msg.payload, SSH_MSG_NEWKEYS):
					raise Exception('Expected NEWKEYS, got %s' % type(msg.payload))

				self.session.cipher = cipher
				self.session.state = 'AUTHENTICATION'
				continue

			elif self.session.state == 'AUTHENTICATION':
				#here should be the atuhentication part
				print('AUTHENTICATION')
				break
				