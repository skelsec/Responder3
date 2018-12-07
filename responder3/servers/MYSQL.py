import enum
import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.MYSQL import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

class MYSQLSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.parser = MYSQLMessageParser(self)
		self.status = MYSQLSessionStatus.INITIAL_HANDSHAKE
		self.server_version = '5.0.54'
		self.server_challenge = 'A'*20 #needs to be string of 20 characters!
		self.sequence_id = 0
		self.auth_type = MYSQLAuthType.SECURE

		self.username = None

	def __repr__(self):
		t = '== MYSQL Session ==\r\n'
		t += 'status:      %s\r\n' % repr(self.status)
		return t


class MYSQL(ResponderServer):
	def init(self):
		pass

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	@r3trafficlogexception
	async def run(self):
		# send protocolversion
		if self.session.auth_type == MYSQLAuthType.SECURE:
			handshake = HandshakeV10_New(self.session.server_version, self.session.server_challenge[:8], self.session.server_challenge[8:])
		elif self.session.auth_type == MYSQLAuthType.PLAIN or self.session.auth_type == MYSQLAuthType.OLD:
			handshake = HandshakeV10_Clear(self.session.server_version, self.session.server_challenge[:8])
		else:
			raise Exception('Auth type not implemented! TODO! %s' % self.auth_type.name)

		await asyncio.wait_for(
				self.send_data(handshake.to_bytes()), timeout=1)	
		self.session.sequence_id += 1	

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

			self.session.sequence_id += 1

			if self.session.status == MYSQLSessionStatus.INITIAL_HANDSHAKE:

				if isinstance(msg, HandshakeResponse41):
					self.session.username = msg.username
					if self.session.auth_type == MYSQLAuthType.SECURE:
						fullhash = '$mysqlna$%s*%s' % (self.session.server_challenge.encode().hex(), msg.auth_response.hex())

						cred = Credential('MYSQL',
						  username=msg.username,
						  fullhash=fullhash
						)
						await self.logger.credential(cred)

						#TODO: implement error message
						return

					elif self.session.auth_type == MYSQLAuthType.PLAIN:
						switch = AuthSwitchRequest_Clear(self.session.sequence_id)
						self.session.status = MYSQLSessionStatus.AUTHENTICATION_SWITCH
						await self.send_data(switch.to_bytes())
						continue

					elif self.session.auth_type == MYSQLAuthType.OLD:
						switch = AuthSwitchRequest_Old(self.session.sequence_id, self.session.server_challenge[:8])
						self.session.status = MYSQLSessionStatus.AUTHENTICATION_SWITCH
						await self.send_data(switch.to_bytes())
						continue

					else:
						raise Exception('Auth type not implemented! TODO! %s' % self.auth_type.name)

					# $mysqlna$1c24ab8d0ee94d70ab1f2e814d8f0948a14d10b9*437e93572f18ae44d9e779160c2505271f85821d 

					#switch = AuthSwitchRequest_Clear(self.session.sequence_id)
					#await self.send_data(switch.to_bytes())
					#switch = HandshakeV10_New(self.session.sequence_id, self.session.server_challenge, '>612IWZ>fhWX')
					#await self.send_data(switch.to_bytes())
					#continue

				else:
					raise Exception('Unexpected packet!')

			elif self.session.status == MYSQLSessionStatus.AUTHENTICATION_SWITCH:

				if isinstance(msg, AuthSwitchResponse):
					if self.session.auth_type == MYSQLAuthType.PLAIN:
						cred = Credential('MYSQL-PLAIN',
						  username=self.session.username,
						  password=msg.auth_plugin_data.decode(),
						  fullhash='%s:%s' % (self.session.username, msg.auth_plugin_data.decode())
						)
						await self.logger.credential(cred)

						#TODO: implement error message
						return

					elif self.session.auth_type == MYSQLAuthType.OLD:
						cred = Credential('MYSQL-OLD',
						  username=self.session.username,
						  fullhash='%s:%s' % (self.session.username, msg.auth_plugin_data)
						)
						await self.logger.credential(cred)

						#TODO: implement error message
						return


				else:
					raise Exception('Unexpected packet!')



			
			