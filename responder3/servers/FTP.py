import enum
import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.FTP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class FTPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.encoding = 'ascii'
		self.parser = FTPCommandParser(encoding=self.encoding)
		self.authhandler = None
		self.creds = {}
		self.current_state = FTPState.AUTHORIZATION
		self.banner = None

	def __repr__(self):
		t = '== FTP Session ==\r\n'
		t += 'encoding:      %s\r\n' % repr(self.encoding)
		t += 'parser: %s\r\n' % repr(self.parser)
		t += 'current_state: %s\r\n' % repr(self.current_state)
		t += 'authhandler: %s\r\n' % repr(self.authhandler)
		return t


class FTP(ResponderServer):
	def init(self):
		if self.settings:
			self.parse_settings()
			return
		self.set_default_settings()

	def set_default_settings(self):
		self.session.banner = 'ProFTPD 1.3.5a Server (ProFTPD)'

	def parse_settings(self):
		if 'banner' in self.settings:
			self.session.banner = self.settings['banner']

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	@r3trafficlogexception
	async def run(self):
		# send hello
		await asyncio.wait_for(
			self.send_data(FTPReply(220, self.session.banner).to_bytes()), timeout=1)
		
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

			#cmd = await asyncio.wait_for(self.parse_message(), timeout=None)
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
							await self.logger.credential(cred)
						if res == FTPAuthStatus.MORE_DATA_NEEDED:
							await asyncio.wait_for(
								self.send_data(FTPReply(331).to_bytes()), timeout=1)
							continue
						elif res == FTPAuthStatus.NO:
							await self.logger.credential(cred)
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
				#raise NotImplementedError
				return
			else:
				raise Exception('Unknown FTP state!')
