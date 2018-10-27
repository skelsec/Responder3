import enum
import logging
import asyncio

from responder3.core.commons import *
from responder3.protocols.FTP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class FTPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.encoding = 'ascii'
		self.parser = FTPCommandParser(encoding=self.encoding)
		self.authhandler = None
		self.creds = None
		self.current_state = FTPState.AUTHORIZATION
		self.log_data = False
		self.welcome_message = 'hello from Honeypot FTP server'

	def __repr__(self):
		t = '== FTP Session ==\r\n'
		t += 'encoding:      %s\r\n' % repr(self.encoding)
		t += 'parser: %s\r\n' % repr(self.parser)
		t += 'current_state: %s\r\n' % repr(self.current_state)
		t += 'authhandler: %s\r\n' % repr(self.authhandler)
		return t


class FTP(ResponderServer):
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
			# send hello
			await asyncio.wait_for(
				self.send_data(FTPReply(220, self.session.welcome_message).to_bytes()), timeout=1)

			# main loop
			while True:
				cmd = await asyncio.wait_for(self.parse_message(), timeout=None)
				if cmd is None:
					return

				if 'R3DEEPDEBUG' in os.environ:
					await self.log(cmd, logging.DEBUG)
					await self.log(self.session.current_state, logging.DEBUG)

				if self.session.log_data:
					pass

				if self.session.current_state == FTPState.AUTHORIZATION:
					if cmd.command in [FTPCommand.USER, FTPCommand.PASS, FTPCommand.QUIT]:
						if cmd.command == FTPCommand.QUIT:
							await asyncio.wait_for(
								self.send_data(FTPReply(200).to_bytes()),
								timeout=1)
							return
						else:
							if self.session.authhandler is None:
								self.session.authhandler = FTPAuthHandler(FTPAuthMethod.PLAIN, self.session.creds)

							res, cred = self.session.authhandler.do_AUTH(cmd)
							if cred is not None:
								await self.log_credential(cred)
							if res == FTPAuthStatus.MORE_DATA_NEEDED:
								await asyncio.wait_for(
									self.send_data(FTPReply(331).to_bytes()), timeout=1)
								continue
							elif res == FTPAuthStatus.NO:
								await self.log_credential(cred)
								await asyncio.wait_for(
									self.send_data(FTPReply(530).to_bytes()), timeout=1)
								return
							elif res == FTPAuthStatus.OK:
								await asyncio.wait_for(
									self.send_data(FTPReply(200).to_bytes()), timeout=1)
								self.session.current_state = FTPState.AUTHENTICATED
								continue
					else:
						await asyncio.wait_for(
							self.send_data(FTPReply(503).to_bytes()), timeout=1)
						return

				elif self.session.current_state == FTPState.AUTHENTICATED:
					raise NotImplementedError

				else:
					raise Exception('Unknown FTP state!')

		except Exception as e:
			await self.log_exception()
			return
