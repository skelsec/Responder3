import enum
import logging
import asyncio
from urllib.parse import urlparse

from responder3.core.commons import *
from responder3.protocols.IMAP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class IMAPSession(ResponderServerSession):
	def __init__(self, *args):
		ResponderServerSession.__init__(self, *args)
		self.encoding     = 'utf-7'
		self.parser       = IMAPCommandParser(encoding = self.encoding)
		self.authhandler  = None
		self.supported_versions = [IMAPVersion.IMAP, IMAPVersion.IMAP4rev1]
		self.additional_capabilities = []
		self.supported_auth_types = [IMAPAuthMethod.PLAIN]
		self.creds = None
		self.current_state = IMAPState.NOTAUTHENTICATED

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

	@asyncio.coroutine
	def parse_message(self, timeout = None):
		try:
			req = yield from asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout = timeout)
			return req
		except asyncio.TimeoutError:
			self.log('Timeout!', logging.DEBUG)

	@asyncio.coroutine
	def send_data(self, data):
		self.cwriter.write(data)
		yield from self.cwriter.drain()

	@asyncio.coroutine
	def run(self):
		try:
			# send hello
			yield from asyncio.wait_for(
				self.send_data(IMAPOKResp.construct('hello from Honeyport IMAP server').to_bytes()),
				timeout = 1
			)
			
			# main loop
			while True:
				cmd = yield from asyncio.wait_for(self.parse_message(), timeout = None)
				if cmd is None:
					#connection closed exception happened in the parsing
					self.session.close_session.set()
					continue
				#print(cmd)
				#print(self.session.current_state)
				
				if self.session.current_state == IMAPState.NOTAUTHENTICATED:
					if cmd.command == IMAPCommand.LOGIN:
						self.session.authhandler = IMAPAuthHandler(IMAPAuthMethod.PLAIN, creds= self.session.creds)
						res, cred = self.session.authhandler.do_AUTH(cmd)
						self.log_credential(cred)
						if res is True:
							self.session.current_state = IMAPState.AUTHENTICATED
							yield from asyncio.wait_for(
								self.send_data(IMAPOKResp.construct('CreZ good!', cmd.tag).to_bytes())
								, timeout = 1
							)
							continue
						else:
							yield from asyncio.wait_for(self.send_data(
								IMAPNOResp.construct('wrong credZ!', cmd.tag).to_bytes()),
								timeout = 1
							)
							return

					elif cmd.command == IMAPCommand.CAPABILITY:
						yield from asyncio.wait_for(
							self.send_data(
								IMAPCAPABILITYResp.construct(
									self.session.supported_versions,
									self.session.supported_auth_types,
									self.session.additional_capabilities
									).to_bytes()
								), timeout = 1)
						yield from asyncio.wait_for(
							self.send_data(
								IMAPOKResp.construct('Completed', cmd.tag).to_bytes()),
								timeout = 1
						)
						continue

				if self.session.current_state == IMAPState.AUTHENTICATED:
					raise NotImplementedError
				
				else:
					raise NotImplementedError
					return
				
					
		except Exception as e:
			self.log_exception()
			return
