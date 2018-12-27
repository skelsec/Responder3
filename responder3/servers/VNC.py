import enum
import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.VNC import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class VNCSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.parser = VNCMessageParser(self)
		self.status = VNCSessionStatus.PROTOCOL_EXCH
		self.protocolversion = None
		self.server_challenge = None

	def __repr__(self):
		t = '== VNC Session ==\r\n'
		t += 'status:      %s\r\n' % repr(self.status)
		return t


class VNC(ResponderServer):
	def init(self):
		if self.settings:
			self.parse_settings()
			return
		self.set_default_settings()

	def set_default_settings(self):
		self.session.protocolversion = 'RFB 003.008\n'
		self.session.server_challenge = b'\x00' * 16

	def parse_settings(self):
		if 'protocolversion' in self.settings:
			self.session.protocolversion = self.settings['protocolversion']
			if self.session.protocolversion[-1] != '\n':
				self.session.protocolversion += '\n'
		if 'server_challenge' in self.settings:
			self.session.server_challenge = bytes.fromhex(self.settings['server_challenge'])

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	@r3trafficlogexception
	async def run(self):
		# send protocolversion
		pv = ProtocolVersion()
		pv.protocolversion = self.session.protocolversion
		await asyncio.wait_for(
				self.send_data(pv.to_bytes()), timeout=1)
			
		if self.session.status == VNCSessionStatus.PROTOCOL_EXCH:
			sh = SecurityHandshake()
			sh.security_types = [VNCSecurityTypes.VNC_AUTHENTICATION]
			await self.send_data(sh.to_bytes())
			self.session.status = VNCSessionStatus.SECURITY
					
		# main loop
		while not self.shutdown_evt.is_set():
			try:
				result = await asyncio.gather(*[asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout=None)], return_exceptions=True)
			except asyncio.CancelledError as e:
				raise e
			if isinstance(result[0], R3ConnectionClosed):
				return
			elif isinstance(result[0], Exception):
				raise result[0]
			else:
				msg = result[0]

					
			if self.session.status == VNCSessionStatus.SECURITY:
				if isinstance(msg, SecurityHandshakeResponse):
					#print('VNC client selected the following hadshake: %s' % msg.security_type.name)
					if not msg.security_type:
						continue
					if msg.security_type != VNCSecurityTypes.NONE:
						#tricky user wants to get in without auth
						cred = Credential('VNC',
							fullhash="<NOT CRED> Attacker tried noauth!"
						)
						await self.logger.credential(cred)
					if msg.security_type != VNCSecurityTypes.VNC_AUTHENTICATION:
						srh = SecurityResultHandshake()
						srh.status = SecurityResultHandshakeStatus.FAILED
						srh.err_reason = 'Authentication type not supported!'
							
						await self.send_data(srh.to_bytes())
						return
		
						#raise Exception('Client returned different authentication type than what the server supports!')
					va = VNCAuthentication()
					va.challenge = self.session.server_challenge
					await self.send_data(va.to_bytes())
					self.session.status = VNCSessionStatus.AUTHENTICATION
					continue
					
			if self.session.status == VNCSessionStatus.AUTHENTICATION:
				if isinstance(msg, VNCAuthenticationResult):
					fullhash = "$vnc$%s$%s" % (self.session.server_challenge.hex(), msg.response.hex())
					cred = Credential('VNC',
						fullhash=fullhash
					)
					await self.logger.credential(cred)
						
					srh = SecurityResultHandshake()
					srh.status = SecurityResultHandshakeStatus.FAILED
					srh.err_reason = 'Password incorrect!'
							
					await self.send_data(srh.to_bytes())
					return
