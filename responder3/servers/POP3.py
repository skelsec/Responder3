import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.POP3 import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class POP3Session(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.encoding = 'ascii'
		self.parser = POP3CommandParser(encoding=self.encoding)
		self.authhandler = None
		self.supported_auth_types = [POP3AuthMethod.PLAIN, POP3AuthMethod.APOP, POP3AuthMethod.AUTH]
		self.creds = {'alma':'alma2'}
		self.salt = '<1896.697170952@dbc.mtview.ca.us>'
		self.current_state = POP3State.AUTHORIZATION
		self.log_data = False
		self.welcome_message = 'hello from Honeypot POP3 server'

	def __repr__(self):
		t = '== POP3 Session ==\r\n'
		t += 'encoding:      %s\r\n' % repr(self.encoding)
		t += 'parser: %s\r\n' % repr(self.parser)
		t += 'current_state: %s\r\n' % repr(self.current_state)
		t += 'authhandler: %s\r\n' % repr(self.authhandler)
		return t


class POP3(ResponderServer):
	def init(self):
		pass

	# self.parse_settings()

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	@r3trafficlogexception
	async def run(self):
		# send hello
		await asyncio.wait_for(
			self.send_data(
				POP3OKResp.construct(
					'%s %s' % (self.session.welcome_message, self.session.salt)).to_bytes()
				),
				timeout=1
		)

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
				cmd = result[0]
				
			if 'R3DEEPDEBUG' in os.environ:
				await self.log(cmd, logging.DEBUG)
				await self.log(self.session.current_state, logging.DEBUG)

			if self.session.current_state == POP3State.AUTHORIZATION:
				if cmd.command in POP3AuthorizationStateCommands:
					capas = ['Capability list follows','USER','.']
					if cmd.command == POP3Command.CAPA:
						await asyncio.wait_for(
							self.send_data(POP3OKResp.construct('\r\n'.join(capas)).to_bytes()),
							timeout=1)
						continue
					
					elif cmd.command == POP3Command.QUIT:
						await asyncio.wait_for(
							self.send_data(POP3OKResp.construct('').to_bytes()),
							timeout=1)
						return
					
					else:
						if self.session.authhandler is None:
							if cmd.command in [POP3Command.USER, POP3Command.PASS]:
								self.session.authhandler = POP3AuthHandler(POP3AuthMethod.PLAIN, self.session.creds, self.session.salt)
							elif cmd.command == POP3Command.APOP and POP3AuthMethod.APOP in self.session.supported_auth_types:
								self.session.authhandler = POP3AuthHandler(POP3AuthMethod.APOP, self.session.creds, self.session.salt)
							elif cmd.command == POP3Command.AUTH and POP3AuthMethod.AUTH in self.session.supported_auth_types:
								self.session.authhandler = POP3AuthHandler(POP3AuthMethod.AUTH, self.session.creds)
							else:
								raise Exception('Auth type not supported!')

						res, data = self.session.authhandler.do_AUTH(cmd)
						
						if res == POP3AuthStatus.MORE_DATA_NEEDED:
							await asyncio.wait_for(
								self.send_data(data),
								timeout=1)
							continue
						
						elif res == POP3AuthStatus.NO:
							await self.logger.credential(data)
							await asyncio.wait_for(
								self.send_data(POP3ERRResp.construct('').to_bytes()),
								timeout=1)
							return
						elif res == POP3AuthStatus.OK:
							await self.logger.credential(data)
							await asyncio.wait_for(
								self.send_data(POP3OKResp.construct('User has no new messages').to_bytes()),
								timeout=1)
							self.session.current_state = POP3State.TRANSACTION
							continue
				else:
					raise Exception('Wrong POP3 command received for AUTHORIZATION state! Command: %s' % cmd.command)
		
			elif self.session.current_state == POP3State.TRANSACTION:
				if cmd.command in POP3TransactionStateCommands:
					raise NotImplementedError
				else:
					raise Exception('Wrong POP3 command received for TRANSACTION state!Command: %s' % cmd.command)

			elif self.session.current_state == POP3State.UPDATE:
				if cmd.command in POP3UpdateStateCommands:
					# be careful QUIT has a different meaning here!
					raise NotImplementedError
				else:
					raise Exception('Wrong POP3 command received for UPDATE state! Command: %s' % cmd.command)

