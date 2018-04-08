import logging
import asyncio
import email.parser

from responder3.core.commons import *
from responder3.protocols.SMTP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class SMTPSession(ResponderServerSession):
	def __init__(self, *args):
		ResponderServerSession.__init__(self, *args)
		self.creds = None # {'alma':'alma2'}
		self.salt = '<1896.697170952@dbc.mtview.ca.us>'
		self.encoding = 'utf8'  # THIS CAN CHANGE ACCORING TO CLIENT REQUEST!!!
		self.parser = SMTPCommandParser(encoding=self.encoding)
		self.emailparser = email.parser.Parser()
		self.current_state = SMTPServerState.START
		self.supported_auth_types = [SMTPAuthMethod.PLAIN, SMTPAuthMethod.CRAM_MD5]
		self.authhandler = None
		self.emailFrom = ''
		self.emailTo = []

		self.capabilities = []
		self.helo_msg = 'Honypot SMTP at your service'
		self.ehlo_msg = 'Honypot SMTP at your service'


	def __repr__(self):
		t = '== SMTP Session ==\r\n'
		t += 'encoding     : %s\r\n' % repr(self.encoding)
		t += 'parser       : %s\r\n' % repr(self.parser)
		t += 'current_state: %s\r\n' % repr(self.current_state)
		t += 'authhandler  : %s\r\n' % repr(self.authhandler)
		return t


class SMTP(ResponderServer):
	def init(self):
		self.parse_settings()

	def parse_settings(self):
		self.session.helo_msg = 'Honypot SMTP at your service'
		self.session.ehlo_msg = 'Honypot SMTP at your service'
		self.session.capabilities.append('SMTPUTF8')
		if self.session.supported_auth_types is not None:
			self.session.capabilities.append('AUTH ' + ' '.join([a.name for a in self.session.supported_auth_types]))

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
				self.send_data(SMTPReply.construct(220, 'hello from Honeyport SMTP server %s' % self.session.salt).to_bytes()), timeout=1)

			# main loop
			while True:
				cmd = yield from asyncio.wait_for(self.parse_message(), timeout=None)
				if cmd is None:
					# connection closed exception happened in the parsing
					self.session.close_session.set()
					continue
				print(cmd)
				print(self.session.current_state)

				if self.session.current_state == SMTPServerState.START:
					if cmd.command == SMTPEHLOCmd or cmd.command == SMTPHELOCmd:
						if self.session.supported_auth_types is None:
							self.session.current_state = SMTPServerState.AUTHENTICATED

					if cmd.command == SMTPCommand.HELO:
						yield from asyncio.wait_for(
							self.send_data(
								SMTPReply.construct(250, [self.session.helo_msg] + self.session.capabilities).to_bytes()),
							timeout=1)
						continue

					elif cmd.command == SMTPCommand.EHLO:
						yield from asyncio.wait_for(
							self.send_data(
								SMTPReply.construct(250, [self.session.ehlo_msg] + self.session.capabilities).to_bytes()),
							timeout=1)
						continue


					elif cmd.command == SMTPCommand.EXPN:
						yield from asyncio.wait_for(
							self.send_data(SMTPReply.construct(502).to_bytes()),
							timeout=1)
						continue

					elif cmd.command == SMTPCommand.VRFY:
						yield from asyncio.wait_for(
							self.send_data(SMTPReply.construct(502).to_bytes()),
							timeout=1)
						continue

					elif cmd.command == SMTPCommand.AUTH:
						self.session.current_state = SMTPServerState.AUTHSTARTED
						# NOTE: the protocol allows the authentication data to be sent immediately by the client
						# if this happens, the initdata will be not none and needs to be evaluated.
						if cmd.mechanism == 'PLAIN':
							self.session.authhandler = SMTPAuthHandler(SMTPAuthMethod.PLAIN, self.session.creds)
							if cmd.data is not None:
								res, cred = self.session.authhandler.do_AUTH(cmd)
								if cred is not None:
									self.logCredential(cred)
								if res == SMTPAuthStatus.OK:
									self.session.current_state = SMTPServerState.AUTHENTICATED
									yield from asyncio.wait_for(
										self.send_data(SMTPReply.construct(235).to_bytes()),
										timeout=1)
									continue
								else:
									yield from asyncio.wait_for(
										self.send_data(SMTPReply.construct(535).to_bytes()),
										timeout=1)
									return
							else:
								yield from asyncio.wait_for(
									self.send_data(SMTPReply.construct(334).to_bytes()),
									timeout=1)
								continue
						else:
							yield from asyncio.wait_for(
								self.send_data(SMTPReply.construct(535).to_bytes()),
								timeout=1)
							raise Exception('Not supported auth mechanism')
					else:
						yield from asyncio.wait_for(
							self.send_data(SMTPReply.construct(503).to_bytes()),
							timeout=1)
						continue

				# this state is only for the authentication part
				elif self.session.current_state == SMTPServerState.AUTHSTARTED:
					"""
					here we expect to have non-smtp conform messages (without command code)
					"""
					if cmd.command == SMTPCommand.XXXX:
						res, cred = self.session.authhandler.do_AUTH(cmd)
						if cred is not None:
							self.logCredential(cred)
						if res == SMTPAuthStatus.MORE_DATA_NEEDED:
							yield from asyncio.wait_for(
								self.send_data(SMTPReply.construct(334).to_bytes()),
								timeout=1)
							continue
						else:
							if res == SMTPAuthStatus.OK:
								self.session.current_state = SMTPServerState.AUTHENTICATED
								yield from asyncio.wait_for(
									self.send_data(SMTPReply.construct(235).to_bytes()),
									timeout=1)
								continue
							else:
								yield from asyncio.wait_for(
									self.send_data(SMTPReply.construct(535).to_bytes()),
									timeout=1)
								return

				# should be checking which commands are allowed in this state...
				elif self.session.current_state == SMTPServerState.AUTHENTICATED:
					if cmd.command == SMTPCommand.MAIL:
						self.session.emailFrom = cmd.emailaddress
						yield from asyncio.wait_for(
							self.send_data(SMTPReply.construct(250).to_bytes()),
							timeout=1)
						continue

					elif cmd.command == SMTPCommand.RCPT:
						self.session.emailTo.append(cmd.emailaddress)
						yield from asyncio.wait_for(
							self.send_data(SMTPReply.construct(250).to_bytes()),
							timeout=1)
						continue

					elif cmd.command == SMTPCommand.DATA:
						# we get data command, switching current_state and sending a reply to client can send data
						if cmd.emaildata is None:
							yield from asyncio.wait_for(
								self.send_data(SMTPReply.construct(354).to_bytes()),
								timeout=1)
							continue
						else:
							em = EmailEntry()
							em.email = self.session.emailparser.parsestr(cmd.emaildata)
							em.fromAddress = self.session.emailFrom  # string
							em.toAddress = self.session.emailTo  # list
							self.logEmail(em)
							yield from asyncio.wait_for(
								self.send_data(SMTPReply.construct(250).to_bytes()),
								timeout=1)
							continue
					else:
						yield from asyncio.wait_for(
							self.send_data(SMTPReply.construct(503).to_bytes()),
							timeout=1)
						return

				else:
					yield from asyncio.wait_for(
						self.send_data(SMTPReply.construct(503).to_bytes()),
						timeout=1)
					return

		except Exception as e:
			self.logexception()
			return
