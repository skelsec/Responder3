import enum
import logging
import asyncio

from responder3.core.commons import *
from responder3.protocols.VNC import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class VNCSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.parser = VNCMessageParser(self)
		self.status = VNCSessionStatus.PROTOCOL_EXCH
		self.protocolversion = 'RFB 003.008\n'
		self.server_challenge = b'\x00' * 16

	def __repr__(self):
		t = '== VNC Session ==\r\n'
		t += 'status:      %s\r\n' % repr(self.status)
		return t


class VNC(ResponderServer):
	def init(self):
		pass

	async def parse_message(self, timeout=None):
		try:
			req = await asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout=timeout)
			return req
		except asyncio.TimeoutError:
			await self.log('Timeout!', logging.DEBUG)
			return None
		except ConnectionClosed:
			return None
		except Exception:
			await self.log_exception()
			return None

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	async def run(self):
		try:
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
					
			while True:
				msg = await self.parse_message()
					
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
							await self.log_credential(cred)
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
						print('Client response: %s' % msg.response.hex())
						fullhash = "$vnc$%s$%s" % (self.session.server_challenge.hex(), msg.response.hex())
						cred = Credential('VNC',
							fullhash=fullhash
						)
						await self.log_credential(cred)
						
						srh = SecurityResultHandshake()
						srh.status = SecurityResultHandshakeStatus.FAILED
						srh.err_reason = 'Password incorrect!'
							
						await self.send_data(srh.to_bytes())
						return
					
				

			

		except Exception as e:
			await self.log_exception()
			return
