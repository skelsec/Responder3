import enum
import logging
import asyncio
from urllib.parse import urlparse

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.IMAP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession
from responder3.core.ssl import *


class IMAPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.encoding     = 'utf-7'
		self.parser       = IMAPCommandParser(encoding = self.encoding)
		self.authhandler  = None
		self.supported_versions = [IMAPVersion.IMAP, IMAPVersion.IMAP4rev1]
		self.additional_capabilities = ['STARTTLS']
		self.supported_auth_types = [IMAPAuthMethod.PLAIN]
		self.creds = {} #None will allow everyone in
		self.current_state = IMAPState.NOTAUTHENTICATED
		self.banner = None
		#self.log_data = False
		self.multiauth_cmd_tag = None #this is for storing the original cmd_tag in case of multiauth was performed
		self.ssl_ctx = None

	def __repr__(self):
		t  = '== IMAPSession ==\r\n'
		t += 'encoding:      %s\r\n' % repr(self.encoding)
		t += 'parser: %s\r\n' % repr(self.parser)
		t += 'current_state: %s\r\n' % repr(self.current_state)
		t += 'authhandler: %s\r\n' % repr(self.authhandler)
		return t


class IMAP(ResponderServer):
	def init(self):
		if self.settings:
			self.parse_settings()
			return
		self.set_default_settings()

	def set_default_settings(self):
		self.session.banner = 'The Microsoft Exchange IMAP4 service is ready.'
		self.session.ssl_ctx = get_default_server_ctx()


	def parse_settings(self):
		if 'banner' in self.settings:
			self.session.banner = self.settings['banner']
		if 'ssl_ctx' in self.settings:
			self.session.ssl_ctx = SSLContextBuilder.from_dict(self.settings['ssl_ctx'])

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	@r3trafficlogexception
	async def run(self):
		# send hello
		await asyncio.wait_for(
			self.send_data(IMAPOKResp.construct(self.session.banner).to_bytes()),
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

			if self.session.current_state == IMAPState.MULTIAUTH:
				res, data = self.session.authhandler.do_AUTH(cmd)
				if res == IMAPAuthStatus.MORE_DATA_NEEDED:
						self.session.current_state = IMAPState.MULTIAUTH
						await asyncio.wait_for(
							self.send_data(data),
							timeout = 1
						)
						continue

				elif res == IMAPAuthStatus.OK:
					await self.logger.credential(data)
					self.session.current_state = IMAPState.AUTHENTICATED
					await asyncio.wait_for(
						self.send_data(IMAPOKResp.construct('LOGIN completed', self.session.multiauth_cmd_tag).to_bytes()),
						timeout = 1
					)
					continue
					
				elif res == IMAPAuthStatus.NO:
					await self.logger.credential(data)
					await asyncio.wait_for(self.send_data(
						IMAPNOResp.construct('wrong credZ!', self.session.multiauth_cmd_tag).to_bytes()),
						timeout = 1
					)
					return
				
				else:
					return

			if self.session.current_state == IMAPState.NOTAUTHENTICATED:
				if cmd.command == IMAPCommand.LOGOUT:
					await asyncio.wait_for(
						self.send_data(
							IMAPBYEResp.construct('').to_bytes()),
							timeout = 1
					)
					return

				if cmd.command == IMAPCommand.STARTTLS:
					self.cwriter.pause_reading()
					await asyncio.wait_for(
						self.send_data(IMAPOKResp.construct('Begin TLS negotiation now', cmd.tag).to_bytes()),
						timeout = 1
					)
					await self.switch_ssl(self.session.ssl_ctx)
					continue

				if cmd.command == IMAPCommand.LOGIN:
					self.session.authhandler = IMAPAuthHandler(IMAPAuthMethod.PLAIN, creds= self.session.creds)
					res, data = self.session.authhandler.do_AUTH(cmd)
					if res == IMAPAuthStatus.MORE_DATA_NEEDED:
						await asyncio.wait_for(
							self.send_data(data),
							timeout = 1
						)
						continue

					elif res == IMAPAuthStatus.OK:
						await self.logger.credential(data)
						self.session.current_state = IMAPState.AUTHENTICATED
						await asyncio.wait_for(
							self.send_data(IMAPOKResp.construct('LOGIN completed', cmd.tag).to_bytes()),
							timeout = 1
						)
						continue
					
					else:
						await self.logger.credential(data)
						await asyncio.wait_for(self.send_data(
							IMAPNOResp.construct('wrong credZ!', cmd.tag).to_bytes()),
							timeout = 1
						)
						return

				elif cmd.command == IMAPCommand.AUTHENTICATE:
					self.session.authhandler = IMAPAuthHandler(cmd.auth_type, creds=self.session.creds)
					res, data = self.session.authhandler.do_AUTH(cmd)
					if res == IMAPAuthStatus.MORE_DATA_NEEDED:
						self.session.current_state = IMAPState.MULTIAUTH
						self.session.multiauth_cmd_tag = cmd.tag
						await asyncio.wait_for(
							self.send_data(data),
							timeout = 1
						)
						continue

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
