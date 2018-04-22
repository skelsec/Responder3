import enum
import logging
import asyncio
from urllib.parse import urlparse

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

	async def parse_message(self, timeout = None):
		try:
			req = await asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout = timeout)
			return req
		except asyncio.TimeoutError:
			await self.log('Timeout!', logging.DEBUG)
			return None
		except ConnectionClosed:
			return None

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	async def run(self):
		try:
			# send hello
			await asyncio.wait_for(
				self.send_data(IMAPOKResp.construct(self.session.welcome_message).to_bytes()),
				timeout = 1
			)
			
			# main loop
			while True:
				cmd = await asyncio.wait_for(self.parse_message(), timeout = None)
				if cmd is None:
					return

				if 'R3DEEPDEBUG' in os.environ:
					await self.log(cmd, logging.DEBUG)
					await self.log(self.session.current_state, logging.DEBUG)

				if self.session.log_data:
					pass

				if self.session.current_state == IMAPState.NOTAUTHENTICATED:
					if cmd.command == IMAPCommand.LOGIN:
						self.session.authhandler = IMAPAuthHandler(IMAPAuthMethod.PLAIN, creds= self.session.creds)
						res, cred = self.session.authhandler.do_AUTH(cmd)
						await self.log_credential(cred)
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

		except Exception as e:
			await self.log_exception()
			return
