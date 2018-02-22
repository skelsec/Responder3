import traceback
import logging
import io
import os
import email.parser
from responder3.utils import ServerFunctionality
from responder3.core.servertemplate import ResponderServer, ResponderProtocolTCP, ProtocolSession, EmailEntry
from responder3.protocols.SMTP import SMTPServerState, SMTPCommandParser, SMTPReply, SMTPCommand
from responder3.servers import AuthClasses

"""
NOPEs list:
STARTSSL
ENHANCEDSTATUSCODES
STARTTLS
DIGEST-MD5
CRAM-MD5
GSSAPI

and a lot more probably
"""

class SMTPSession(ProtocolSession):
	def __init__(self):
		ProtocolSession.__init__(self)
		self.encoding     = 'utf8' #THIS CAN CHANGE ACCORING TO CLIENT REQUEST!!!
		self.cmdParser    = SMTPCommandParser(encoding = self.encoding)
		self.emailParser  = email.parser.Parser()
		self.currentState = SMTPServerState.START
		self.authAPI      = None
		self.emailData    = ''
		self.emailFrom    = ''
		self.emailTo      = []


class SMTPProtocol(ResponderProtocolTCP):
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)
		self._buffer_maxsize = 1*1024
		self._session = SMTPSession()

	def _connection_made(self):
		self._server.sendWelcome(self._transport)


	def _parsebuff(self):
		if self._session.currentState == SMTPServerState.DATAINCOMING:
			while True:
				marker = self._buffer.find(b'\n')
				if marker == -1:
					break

				dataend = self._buffer.find(b'\r\n.\r\n')
				if dataend == -1:
					self._session.emailData += self._buffer[:marker + 1].decode(self._session.encoding)
					self._buffer = self._buffer[marker + 1:]

				
				else:
					self._session.emailData += self._buffer[:dataend + 5].decode(self._session.encoding)
					self._buffer = self._buffer[dataend + 5:]
					self._session.currentState = SMTPServerState.DATAFINISHED
					self._server.handle(None, self._transport, self._session)

				if self._buffer != b'':
					self._parsebuff()
				else:
					break

		else:
		
			#SMTP commands are terminated by new line chars
			#here we grabbing one command from the buffer, and parsing it
			marker = self._buffer.find(b'\n')
			if marker == -1:
				return

			cmd = self._session.cmdParser.parse(io.BytesIO(self._buffer[:marker+1]))

			#after parsing it we send it for processing to the handle
			self._server.handle(cmd, self._transport, self._session)

			#IMPORTANT STEP!!!! ALWAYS CLEAR THE BUFFER FROM DATA THAT IS DEALT WITH!
			self._buffer = self._buffer[marker + 1 :]
			
			if self._buffer != b'':
				self._parsebuff()


class SMTP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)

	def setup(self):
		self.protocol = SMTPProtocol

		#### adjusting configuration
		if self.settings is None:
			self.log(logging.INFO, 'No settings defined, adjusting to Honeypot functionality!')
			self.settings = { 
							  'functionality'  : ServerFunctionality.HONEYPOT,
							  'credentials'    : None,
							  'authTypes'      : ['PLAIN'], #['PLAIN'],
							  'wecomeMsg'      : 'hello from Honeyport SMTP server',
							  'heloMsg'        : 'Honypot SMTP at your service', 
							  'ehloMsg'        : 'Honypot SMTP at your service', 
							  'VRFYresponse'   : None,
							  'startSSLConfig' : None,
							}

		self.capabilities = []
		self.capabilities.append('SMTPUTF8')
		if 'authTypes' in self.settings and self.settings['authTypes'] is not None:
			self.capabilities.append('AUTH '+' '.join(self.settings['authTypes']))
		if 'startSSLConfig' in self.settings and self.settings['startSSLConfig'] is not None:
			self.capabilities.append('STARTTLS')



	def modulename(self):
		return 'SMTP'

	def sendWelcome(self, transport):
		r = SMTPReply()
		r.construct(220, 'hello from Honeyport POP3 server')
		transport.write(r.toBytes())

	def handle(self, smtpcommand, transport, session):
		try:
			if 'R3DEEPDEBUG' in os.environ:
				self.log(logging.INFO,'Session state: %s Command: %s' % (session.currentState.name, smtpcommand.command.name if smtpcommand is not None else 'NONE'), session)
			#should be checking which commands are allowed in this state...
			if session.currentState == SMTPServerState.START:
				if smtpcommand.command == SMTPCommand.EHLO or smtpcommand.command == SMTPCommand.HELO:
					if 'authTypes' in self.settings and self.settings['authTypes'] is None:
						session.currentState = SMTPServerState.AUTHENTICATED
					else:
						session.currentState = SMTPServerState.NOTAUTHETICATED
			
				if smtpcommand.command == SMTPCommand.HELO:
					transport.write(SMTPReply(250, [self.settings['heloMsg']] + self.capabilities).toBytes())

				elif smtpcommand.command == SMTPCommand.EHLO:
					transport.write(SMTPReply(250, [self.settings['ehloMsg']] + self.capabilities).toBytes())


			elif session.currentState == SMTPServerState.NOTAUTHETICATED:
				if smtpcommand.command == SMTPCommand.VRFY:
					self.log(logging.INFO,'VERIFY called with data: %s' % (smtpcommand.data), session)
					transport.write(SMTPReply(250, ['test@test.com','donthackme@aaa.com']).toBytes())

				elif smtpcommand.command == SMTPCommand.EXPN:
					transport.write(SMTPReply(502).toBytes())

				elif smtpcommand.command == SMTPCommand.AUTH:
					session.currentState = SMTPServerState.AUTHSTARTED
					### NOTE: the protocol allows the authentication data to be sent immediately by the client
					### if this happens, the initdata will be not none and needs to be evaluated.
					if smtpcommand.mechanism == 'PLAIN':
						session.authAPI = AuthClasses.PLAIN(self.settings['credentials'])
						if smtpcommand.initresp is not None:
							session.authAPI.setAuthData(smtpcommand.initresp)

							self.logResult(session, {
							'type'     : 'Cleartext', 
							'client'   : session.connection.remote_ip, 
							'user'     : session.authAPI._username,
							'cleartext': session.authAPI._password, 
							'fullhash' : session.authAPI._username + ':' + session.authAPI._password
							})

							if session.authAPI.checkCredentials():
								session.currentState = SMTPServerState.AUTHENTICATED
								transport.write(SMTPReply(235).toBytes())

							else:
								transport.write(SMTPReply(535).toBytes())
						else:
							transport.write(SMTPReply(535).toBytes())
					else:
						transport.write(SMTPReply(535).toBytes())
						raise Exception('Not supported auth mechanism')
				else:
					transport.write(SMTPReply(503).toBytes())

			#this state is only for the authentication part
			elif session.currentState == SMTPServerState.AUTHSTARTED:
				"""
				here we expect to have non-smtp conform messages (without command code)
				"""
				if smtpcommand.command == SMTPCommand.XXXX:
					if smtpcommand.mechanism == 'PLAIN':
						session.authAPI.setAuthData(smtpcommand.raw_data)
						if session.authAPI.isMoreData():
							transport.write(SMTPReply(334).toBytes())
						else:
							
							self.logResult(session, {
							'type'     : 'Cleartext', 
							'client'   : session.connection.remote_ip, 
							'user'     : session.authAPI._username,
							'cleartext': session.authAPI._password, 
							'fullhash' : session.authAPI._username + ':' + session.authAPI._password
							})

							if session.authAPI.checkCredentials(smtpcommand.initresp):
								session.currentState = SMTPServerState.AUTHENTICATED
								transport.write(SMTPReply(235).toBytes())
							else:
								transport.write(SMTPReply(535).toBytes())

			
			#should be checking which commands are allowed in this state...
			elif session.currentState == SMTPServerState.AUTHENTICATED:
				if smtpcommand.command == SMTPCommand.MAIL:
					session.emailFrom    = smtpcommand.emailFrom
					transport.write(SMTPReply(250).toBytes())

				elif  smtpcommand.command == SMTPCommand.RCPT:
					session.emailTo.append(smtpcommand.emailTo)
					transport.write(SMTPReply(250).toBytes())

				elif smtpcommand.command == SMTPCommand.DATA:
					#we get data command, switching currentstate and sending a reply to client can send data
					session.currentState = SMTPServerState.DATAINCOMING
					transport.write(SMTPReply(354).toBytes())

				else:
					transport.write(SMTPReply(503).toBytes())

					
			elif session.currentState == SMTPServerState.DATAFINISHED:
				em = EmailEntry()
				em.email = session.emailParser.parsestr(session.emailData)
				em.fromAddress = session.emailFrom #string
				em.toAddress   = session.emailTo #list
				self.logEmail(session, em)

				transport.write(SMTPReply(250).toBytes())

			else:
				transport.write(SMTPReply(503).toBytes())


		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),), session)
			pass
