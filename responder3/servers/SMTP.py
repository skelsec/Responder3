import traceback
import logging
import io
import email.parser
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP, ProtocolSession, EmailEntry
from responder3.newpackets.SMTP import SMTPServerState, SMTPCommandParser, SMTPReply, SMTPCommand
from responder3.servers import AuthClasses

class SMTPSession(ProtocolSession):
	def __init__(self, server):
		ProtocolSession.__init__(self, server)
		self.encoding     = 'ascii' #THIS CAN CHANGE ACCORING TO CLIENT REQUEST!!!
		self.cmdParser    = SMTPCommandParser(self.encoding)
		self.emailParser  = email.parser.Parser()
		self.currentState = SMTPServerState.START
		self.authAPI      = None
		self.emailData    = ''
		self.emailFrom    = ''
		self.emailTo      = ''


class SMTPProtocol(ResponderProtocolTCP):
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)
		self._buffer_maxsize = 1*1024
		self._session = SMTPSession(server.rdnsd)

	def _connection_made(self):
		self._server.sendWelcome(self._transport)

	def _data_received(self, raw_data):
		return

	def _connection_lost(self, exc):
		return

	def _parsebuff(self):
		if self._session.currentState == SMTPServerState.DATAINCOMING:
			while True:
				marker = self._buffer.find(b'\n')
				if marker == -1:
					break
				
				self._session.emailData += self._buffer[:marker+1].decode(self._session.encoding)
				self._buffer = self._buffer[marker + 2 :]
				
				print(self._session.emailData[-5:])
				if self._session.emailData[-5:] == '\r\n.\r\n':
					self._session.currentState = SMTPServerState.DATAFINISHED
					self._server.handle(None, self._transport, self._session)
					return

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
		self._buffer = self._buffer[marker + 2 :]


class SMTP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)

	def setup(self):
		self.protocol = SMTPProtocol

	def modulename(self):
		return 'SMTP'

	def sendWelcome(self, transport):
		r = SMTPReply()
		r.construct(220, 'hello from Honeyport POP3 server')
		transport.write(r.toBytes())

	"""
	502 : 'Command not implemented', #(see Section 4.2.4)
	503 : 'Bad sequence of commands',
	"""

	def handle(self, smtpcommand, transport, session):
		try:
			print(smtpcommand)
			#should be checking which commands are allowed in this state...
			if session.currentState== SMTPServerState.START:
				if smtpcommand.command == SMTPCommand.HELO or smtpcommand.command == SMTPCommand.EHLO:
					session.currentState = SMTPServerState.NOTAUTHETICATED
					transport.write(SMTPReply(250, ['Honypot SMTP at your service','AUTH PLAIN']).toBytes())


			elif session.currentState == SMTPServerState.NOTAUTHETICATED:
				if smtpcommand.command == SMTPCommand.VRFY:
					self.log(session, logging.INFO,'VERIFY called with data: %s' % (smtpcommand.data))
					transport.write(SMTPReply(250, ['test@test.com','donthackme@aaa.com']).toBytes())

				elif smtpcommand.command == SMTPCommand.EXPN:
					transport.write(SMTPReply(502).toBytes())

				elif smtpcommand.command == SMTPCommand.AUTH:
					session.currentState = SMTPServerState.AUTHSTARTED
					print(repr(smtpcommand.mechanism))
					print(repr(smtpcommand.initresp))
					### NOTE: the protocol allows the authentication data to be sent immediately by the client
					### if this happens, the initdata will be not none and needs to be evaluated.
					if smtpcommand.mechanism == 'PLAIN':
						session.authAPI = AuthClasses.PLAIN(None)
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
							transport.write(SMTPReply(334).toBytes())
					else:
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
					print(session.emailData)
					print(smtpcommand.emailFrom)
					session.emailData += smtpcommand.emailFrom + '\r\n'
					transport.write(SMTPReply(250).toBytes())

				elif  smtpcommand.command == SMTPCommand.RCPT:
					session.emailData += '<' + ','.join(smtpcommand.emailTo) + '>\r\n'
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
			self.log(session, logging.INFO,'Exception! %s' % (str(e),))
			pass
