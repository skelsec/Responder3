import logging
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP
from base64 import b64decode
from responder3.packets import SMTPGreeting, SMTPAUTH, SMTPAUTH1, SMTPAUTH2, SMTPauthfail

class SMTPProtocol(ResponderProtocolTCP):
	
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)
		self._buffer_maxsize = 1*1024

	def _connection_made(self, transport):
		self._server.curstate = 0
		self._server.handle(None, transport)

	def _data_received(self, raw_data):
		return

	def _connection_lost(self, exc):
		return

	def _parsebuff(self):
		if len(self._buffer) >= self._buffer_maxsize:
			raise Exception('Input data too large!')

		endpos = self._buffer.find('\r\n')
		if endpos != -1:
			cmd = SMTPCommand(self._buffer[:endpos])
			self._server.handle(cmd,self._transport)
			self._buffer = self._buffer[endpos+2:]

class SMTP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		self.curstate = 0
		self.User = None
		self.Pass = None


	def modulename(self):
		return 'SMTP'

	def run(self):

		coro = self.loop.create_server(
							protocol_factory=lambda: SMTPProtocol(self),
							host="",
							port=self.port
		)

		return self.loop.run_until_complete(coro)

	def handle(self, smtpcommand, transport):
		try:
			if self.curstate == 0:
				transport.write(SMTPGreeting().getdata())
				self.curstate = 1
				return
			
			elif self.curstate == 1:
				if smtpcommand.cmd == "EHLO":
					transport.write(SMTPAUTH().getdata())
					self.curstate = 2
					return

			elif self.curstate == 2:
				if smtpcommand.cmd == "AUTH":
					if smtpcommand.data[0].upper() == "PLAIN":
						authdata = b64decode(smtpcommand.data[1])
						if authdata.count(b'\x00') != 2:
							raise Exception('Auth data doesnt seem right!')
						t, self.User, self.Pass = [x.decode() for x in authdata.split(b'\x00')]

						self.logResult({
							'module': self.modulename(), 
							'type': 'Cleartext', 
							'client': self.peername, 
							'user': self.User, 
							'cleartext': self.Pass, 
							'fullhash': self.User + ':' + self.Pass
						})

						transport.write(SMTPAUTH1().getdata())
						return

					elif smtpcommand.data[0].upper() == "LOGIN":
						self.User = b64decode(smtpcommand.data[1]).decode()
						transport.write(SMTPAUTH2().getdata())
						return
				
				else:
					#at this point the stmpcommand can be either just the password, or credentais in the following format: \x00USER\x00PASSWORD
					authdata = b64decode(smtpcommand.rawdata) 
					if authdata.count(b'\x00') == 2:
						t, self.User, self.Pass = [x.decode() for x in authdata.split(b'\x00')]

						self.logResult({
							'module': self.modulename(), 
							'type': 'Cleartext', 
							'client': self.peername, 
							'user': self.User, 
							'cleartext': self.Pass, 
							'fullhash': self.User + ':' + self.Pass
						})

					else:
						self.Pass = authdata.decode()
						self.logResult({
								'module': self.modulename(), 
								'type': 'Cleartext', 
								'client': self.peername, 
								'user': self.User, 
								'cleartext': self.Pass, 
								'fullhash': self.User + ':' + self.Pass
							})

					transport.write(SMTPAUTH2().getdata())
					return

		except Exception as e:
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			pass

class SMTPCommand():
	def __init__(self, data):
		self.rawdata = data
		self.cmd = ''
		self.data = ''
		self.parse()

	def parse(self):
		if self.rawdata.count(' ') > 0:
			self.cmd = self.rawdata.split(' ')[0].upper()
			self.data = self.rawdata.split(' ')[1:]
		else:
			#not a command, probably auth creds
			return
