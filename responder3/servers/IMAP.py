import logging
import traceback
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP
from responder3.newpackets.IMAP import *

class IMAP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		self.protocol = IMAPProtocol
		self.curstate = IMAPState.NOTAUTHENTICATED
		self.User = None
		self.Pass = None


	def modulename(self):
		return 'IMAP'

	def sendWelcome(self, transport):
		r = IMAPResponse()
		r.construct('*', IMAPServerResponse.OK, 'hello from Honeyport IMAP server')
		transport.write(r.toBytes())

	def handle(self, packet, transport):
		try:
			self.log(logging.DEBUG,'Handle called with data: ' + str(packet))

			if self.curstate == IMAPState.NOTAUTHENTICATED:
				if packet.command == IMAPClientCommand.LOGIN:
					self.User = packet.args[0]
					self.Pass = packet.args[1]
					self.check_credentials(packet, transport)
					return

				elif packet.command == IMAPClientCommand.CAPABILITY:
					r = IMAPResponse()
					r.construct('*', IMAPServerResponse.CAPABILITY, ['IMAP4','IMAP4rev1','AUTH=PLAIN'])
					transport.write(r.toBytes())
					r = IMAPResponse()
					r.construct(packet.tag, IMAPServerResponse.OK, ['Completed'])
					transport.write(r.toBytes())
					return

			else:
				raise Exception('not implemented!')
				transport.close()


		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			transport.close()
			pass

	def check_credentials(self, packet, transport):
		self.log_credentials()
		
		if self.User == 'aaaaaaaaaa' and self.Pass == 'bbbbbbb124234123':
			#login sucsess
			self.curstate = IMAPState.AUTHENTICATED
			r = IMAPResponse()
			r.construct(packet.tag, IMAPServerResponse.OK, 'CreZ good!')
			transport.write(r.toBytes())
		else:
			r = IMAPResponse()
			r.construct(packet.tag, IMAPServerResponse.NO, 'wrong credZ!')
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

class IMAPProtocol(ResponderProtocolTCP):
	
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
		#IMAP commands are terminated by new line chars
		#here we grabbing one command from the buffer, and parsing it
		marker = self._buffer.find(b'\r\n')
		if marker == -1:
			return
	
		cmd = IMAPCommand(io.BytesIO(self._buffer[:marker+2]))

		#after parsing it we send it for processing to the handle
		self._server.handle(cmd, self._transport)

		#IMPORTANT STEP!!!! ALWAYS CLEAR THE BUFFER FROM DATA THAT IS DEALT WITH!
		self._buffer = self._buffer[marker + 2 :]


class IMAPS(IMAP):
	def modulename(self):
		return 'IMAPS'