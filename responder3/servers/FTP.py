import logging
import traceback
import socket
import io
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP
from responder3.newpackets.FTP import * 
#FTPPacket

class FTP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		self.protocol = FTPProtocol
		self.User = None
		self.Pass = None


	def modulename(self):
		return 'FTP'

	def sendWelcome(self, transport):
		r = FTPReply()
		r.construct(220, 'Honeypot FTP server')
		transport.write(r.toBytes())

	def handle(self, ftpcmd, transport):
		try:
			self.log(logging.DEBUG,'Handle called with data: ' + repr(ftpcmd))
			if ftpcmd.command == FTPCommandCode.AUTH:
				r = FTPReply()
				r.construct(502)
				transport.write(r.toBytes())
				return

			if self.User is None:
				if ftpcmd.command == FTPCommandCode.USER:
					self.User = ftpcmd.params['username']
					r = FTPReply()
					r.construct(331, 'User name okay, need password.')
					transport.write(r.toBytes())
					return

				else:
					r = FTPReply()
					r.construct(502)
					transport.write(r.toBytes())
					return

			if self.User is not None:
				if ftpcmd.command == FTPCommandCode.PASS:
					self.Pass = ftpcmd.params['password']

					self.logResult({
						'module': self.modulename(), 
						'type': 'Cleartext', 
						'client': self.peername, 
						'user': self.User, 
						'cleartext': self.Pass, 
						'fullhash': self.User + ':' + self.Pass
					})

					r = FTPReply()
					r.construct(530)
					transport.write(r.toBytes())

				else:
					r = FTPReply()
					r.construct(503)
					transport.write(r.toBytes())
					transport.close()
					return
				
			else:
				r = FTPReply()
				r.construct(502)
				transport.write(r.toBytes())
				return
	

		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			pass
		


class FTPProtocol(ResponderProtocolTCP):
	
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
		#FTP commands are terminated by new line chars
		#here we grabbing one command from the buffer, and parsing it
		while True:
			marker = self._buffer.find(b'\r\n')
			if marker == -1:
				return
		
			cmd = FTPCommand(io.BytesIO(self._buffer[:marker]))

			#after parsing it we send it for processing to the handle
			self._server.handle(cmd, self._transport)

			#IMPORTANT STEP!!!! ALWAYS CLEAR THE BUFFER FROM DATA THAT IS DEALT WITH!
			self._buffer = self._buffer[marker + 2 :]
