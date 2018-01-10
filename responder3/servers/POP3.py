import logging
import traceback
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP
from responder3.newpackets.POP3 import *

class POP3(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		self.protocol = POP3Protocol
		self.curstate = POP3State.AUTHORIZATION
		self.User = None
		self.Pass = None


	def modulename(self):
		return 'POP3'

	def sendWelcome(self, transport):
		r = POP3Response()
		r.construct(POP3ResponseStatus.OK, 'hello from Honeyport POP3 server')
		transport.write(r.toBytes())

	def handle(self, packet, transport):
		try:
			self.log(logging.DEBUG,'Handle called with data: ' + repr(packet))

			if self.curstate == POP3State.AUTHORIZATION:
				if packet.command == POP3Keyword.USER:
					self.User = packet.args[0]
					if self.Pass is not None:
						self.check_credentials(transport)
					else:	
						r = POP3Response()
						r.construct(POP3ResponseStatus.OK, 'password required.')
						transport.write(r.toBytes())
					return

				elif packet.command == POP3Keyword.PASS:
					self.Pass = packet.args[0]
					if self.User is not None:
						self.check_credentials(transport)
					else:
						r = POP3Response()
						r.construct(POP3ResponseStatus.OK, 'password required.')
						transport.write(r.toBytes())
					return

				elif packet.command == POP3Keyword.QUIT:
					self.curstate = POP3State.UPDATE
					r = POP3Response()
					r.construct(POP3ResponseStatus.OK, 'Goodbye!')
					transport.write(r.toBytes())
					transport.close()
					return

				else:
					r = POP3Response()
					r.construct(POP3ResponseStatus.ERR, 'Auth req.')
					transport.write(r.toBytes())
					return

			elif self.curstate == POP3State.TRANSACTION:
				r = POP3Response()
				r.construct(POP3ResponseStatus.OK, 'Goodbye!')
				transport.write(r.toBytes())
				transport.close()
				raise Exception('Not implemented!')
				
				return
				#ransport.write(POPOKPacket().getdata())

			
			else:
				r = POP3Response()
				r.construct(POP3ResponseStatus.OK, 'Goodbye!')
				transport.write(r.toBytes())
				transport.close()
				return


		except Exception as e:
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			pass

	def check_credentials(self, transport):
		self.log_credentials()
		
		if self.User == 'aaaaaaaaaa' and self.Pass == 'bbbbbbb124234123':
			#login sucsess
			self.curstate = POP3State.TRANSACTION
			r = POP3Response()
			r.construct(POP3ResponseStatus.OK, 'CreZ good!')
			transport.write(r.toBytes())
		else:
			r = POP3Response()
			r.construct(POP3ResponseStatus.ERR, 'wrong credZ!')
			transport.write(r.toBytes())
			transport.close()

	def log_credentials(self):
		self.logResult({
						'module': self.modulename(), 
						'type': 'Cleartext', 
						'client': self.peername, 
						'user': self.User, 
						'cleartext': self.Pass, 
						'fullhash': self.User + ':' + self.Pass
					})

class POP3Protocol(ResponderProtocolTCP):
	
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)
		self._buffer_maxsize = 1*1024

	def _connection_made(self, transport):
		self._server.sendWelcome(transport)

	def _data_received(self, raw_data):
		return

	def _connection_lost(self, exc):
		return

	def _parsebuff(self):
		#POP3 commands are terminated by new line chars
		#here we grabbing one command from the buffer, and parsing it
		marker = self._buffer.find(b'\r\n')
		if marker == -1:
			return
	
		cmd = POP3Command(io.BytesIO(self._buffer[:marker]))

		#after parsing it we send it for processing to the handle
		self._server.handle(cmd, self._transport)

		#IMPORTANT STEP!!!! ALWAYS CLEAR THE BUFFER FROM DATA THAT IS DEALT WITH!
		self._buffer = self._buffer[marker + 2 :]

class POP3S(POP3):
	def modulename(self):
		return 'POP3S'