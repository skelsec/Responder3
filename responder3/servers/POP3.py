import logging
import asyncio

from responder3.core.commons import *
from responder3.protocols.POP3 import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class POP3Session(ResponderServerSession):
	def __init__(self, *args):
		ResponderServerSession.__init__(self, *args)
		self.encoding = 'ascii'
		self.parser = POP3CommandParser(encoding=self.encoding)
		self.authhandler = None
		self.supported_auth_types = [POP3AuthMethod.PLAIN, POP3AuthMethod.APOP]
		self.creds = {'alma':'alma2'}
		self.salt = '<1896.697170952@dbc.mtview.ca.us>'
		self.current_state = POP3State.AUTHORIZATION

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
				self.send_data(POP3OKResp.construct('hello from Honeyport POP3 server %s' % self.session.salt).to_bytes()), timeout=1)

			# main loop
			while True:
				cmd = yield from asyncio.wait_for(self.parse_message(), timeout=None)
				if cmd is None:
					# connection closed exception happened in the parsing
					self.session.close_session.set()
					continue
				print(cmd)
				print(self.session.current_state)

				if self.session.current_state == POP3State.AUTHORIZATION:
					if cmd.command in POP3AuthorizationStateCommands:
						if cmd.command == POP3Command.QUIT:
							yield from asyncio.wait_for(
								self.send_data(POP3OKResp.construct('').to_bytes()),
								timeout=1)
							return
						else:
							if self.session.authhandler is None:
								if cmd.command in [POP3Command.USER, POP3Command.PASS]:
									self.session.authhandler = POP3AuthHandler(POP3AuthMethod.PLAIN, self.session.creds, self.session.salt)
								elif cmd.command == POP3Command.APOP and POP3AuthMethod.APOP in self.session.supported_auth_types:
									self.session.authhandler = POP3AuthHandler(POP3AuthMethod.APOP, self.session.creds, self.session.salt)
								else:
									raise Exception('Auth type not supported!')

							res, cred = self.session.authhandler.do_AUTH(cmd)
							print(res)
							if cred is not None:
								self.logCredential(cred)
							if res == POP3AuthStatus.MORE_DATA_NEEDED:
								yield from asyncio.wait_for(
									self.send_data(POP3OKResp.construct('').to_bytes()),
									timeout=1)
								continue
							elif res == POP3AuthStatus.NO:
								self.logCredential(cred)
								yield from asyncio.wait_for(
									self.send_data(POP3ERRResp.construct('').to_bytes()),
									timeout=1)
								return
							elif res == POP3AuthStatus.OK:
								yield from asyncio.wait_for(
									self.send_data(POP3OKResp.construct('User has no new messages').to_bytes()),
									timeout=1)
								self.session.current_state = POP3State.TRANSACTION
								continue
					else:
						raise Exception('Wrong POP3 command received for AUTHORIZATION state!')

				elif self.session.current_state == POP3State.TRANSACTION:
					if cmd.command in POP3TransactionStateCommands:
						raise NotImplementedError
					else:
						raise Exception('Wrong POP3 command received for TRANSACTION state!')

				elif self.session.current_state == POP3State.UPDATE:
					if cmd.command in POP3UpdateStateCommands:
						# be careful QUIT has a different meaning here!
						raise NotImplementedError
					else:
						raise Exception('Wrong POP3 command received for UPDATE state!')

		except Exception as e:
			self.logexception()
			return
