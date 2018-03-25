import enum
import logging
import asyncio

from responder3.core.commons import *
from responder3.protocols.FTP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class FTPSession(ResponderServerSession):
	def __init__(self, *args):
		ResponderServerSession.__init__(self, *args)
		self.encoding = 'ascii'
		self.parser = FTPCommandParser(encoding=self.encoding)
		self.authhandler = None
		self.creds = None
		self.current_state = FTPState.AUTHORIZATION

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

	# self.parse_settings()

	@asyncio.coroutine
	def parse_message(self, timeout=None):
		try:
			req = yield from asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout=timeout)
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
				self.send_data(FTPReply(220, 'Honeypot FTP server').to_bytes()), timeout=1)

			# main loop
			while True:
				cmd = yield from asyncio.wait_for(self.parse_message(), timeout=None)
				if cmd is None:
					# connection closed exception happened in the parsing
					self.session.close_session.set()
					continue
				print(cmd)
				print(self.session.current_state)

				if self.session.current_state == FTPState.AUTHORIZATION:
					if cmd.command in [FTPCommand.USER, FTPCommand.PASS, FTPCommand.QUIT]:
						if cmd.command == FTPCommand.QUIT:
							yield from asyncio.wait_for(
								self.send_data(FTPReply(200).to_bytes()),
								timeout=1)
							return
						else:
							if self.session.authhandler is None:
								self.session.authhandler = FTPAuthHandler(FTPAuthMethod.PLAIN, self.session.creds)

							res, cred = self.session.authhandler.do_AUTH(cmd)
							print(res)
							if cred is not None:
								self.logCredential(cred)
							if res == FTPAuthStatus.MORE_DATA_NEEDED:
								yield from asyncio.wait_for(
									self.send_data(FTPReply(331).to_bytes()), timeout=1)
								continue
							elif res == FTPAuthStatus.NO:
								self.logCredential(cred)
								yield from asyncio.wait_for(
									self.send_data(FTPReply(530).to_bytes()), timeout=1)
								return
							elif res == FTPAuthStatus.OK:
								yield from asyncio.wait_for(
									self.send_data(FTPReply(200).to_bytes()), timeout=1)
								self.session.current_state = FTPState.AUTHENTICATED
								continue
					else:
						yield from asyncio.wait_for(
							self.send_data(FTPReply(503).to_bytes()), timeout=1)
						return

				elif self.session.current_state == POP3State.AUTHENTICATED:
					raise NotImplementedError

				else:
					raise Exception('Unknown FTP state!')

		except Exception as e:
			self.logexception()
			return
