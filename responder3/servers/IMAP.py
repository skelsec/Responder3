import enum
import logging
import asyncio
from urllib.parse import urlparse

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.IMAP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class IMAPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.encoding     = 'utf-7'
		self.parser       = IMAPCommandParser(encoding = self.encoding)
		self.authhandler  = None
		self.supported_versions = [IMAPVersion.IMAP, IMAPVersion.IMAP4rev1]
		self.additional_capabilities = []
		self.supported_auth_types = [IMAPAuthMethod.PLAIN]
		self.creds = None
		self.current_state = IMAPState.NOTAUTHENTICATED
		self.welcome_message = 'hello from Honeyport IMAP server'
		self.log_data = False

	def __repr__(self):
		t  = '== IMAPSession ==\r\n'
		t += 'encoding:      %s\r\n' % repr(self.encoding)
		t += 'parser: %s\r\n' % repr(self.parser)
		t += 'current_state: %s\r\n' % repr(self.current_state)
		t += 'authhandler: %s\r\n' % repr(self.authhandler)
		return t


class IMAP(ResponderServer):
	def init(self):
		pass
		#self.parse_settings()

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	@r3trafficlogexception
	async def run(self):
		# send hello
		await asyncio.wait_for(
			self.send_data(IMAPOKResp.construct(self.session.welcome_message).to_bytes()),
			timeout = 1
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
				await self.logger.debug(cmd)
				await self.logger.debug(self.session.current_state)

			if self.session.current_state == IMAPState.NOTAUTHENTICATED:
				if cmd.command == IMAPCommand.LOGIN:
					self.session.authhandler = IMAPAuthHandler(IMAPAuthMethod.PLAIN, creds= self.session.creds)
					res, cred = self.session.authhandler.do_AUTH(cmd)
					await self.logger.credential(cred)
					if res is True:
						self.session.current_state = IMAPState.AUTHENTICATED
						await asyncio.wait_for(
							self.send_data(IMAPOKResp.construct('LOGIN completed', cmd.tag).to_bytes()),
							timeout = 1
						)
						continue
					else:
						await asyncio.wait_for(self.send_data(
							IMAPNOResp.construct('wrong credZ!', cmd.tag).to_bytes()),
							timeout = 1
						)
						return

				elif cmd.command == IMAPCommand.CAPABILITY:
					await asyncio.wait_for(
						self.send_data(
							IMAPCAPABILITYResp.construct(
								self.session.supported_versions,
								self.session.supported_auth_types,
								self.session.additional_capabilities
								).to_bytes()
							), timeout = 1)
					await asyncio.wait_for(
						self.send_data(
							IMAPOKResp.construct('Completed', cmd.tag).to_bytes()),
							timeout = 1
					)
					continue

			if self.session.current_state == IMAPState.AUTHENTICATED:
				raise NotImplementedError
			
			else:
				raise NotImplementedError
