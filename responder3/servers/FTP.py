import os
import logging
import traceback
import socket
import io
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP, ProtocolSession
from responder3.newpackets.FTP import * 

class FTPSession(ProtocolSession):
	def __init__(self, server):
		ProtocolSession.__init__(self, server)
		self.encoding     = 'ascii'
		self.cmdParser    = FTPCommandParser(encoding = self.encoding)
		self.currentState = FTPState.AUTHORIZATION
		self.User = None
		self.Pass = None

class FTP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		self.protocol = FTPProtocol

	def modulename(self):
		return 'FTP'

	def sendWelcome(self, transport):
		transport.write(FTPReply(220, 'Honeypot FTP server').toBytes())

	def handle(self, packet, transport, session):
		try:
			if 'R3DEEPDEBUG' in os.environ:
				self.log(logging.INFO,'Session state: %s Command: %s' % (session.currentState.name, packet.cmd.name if packet is not None else 'NONE'), session)

			if session.currentState == FTPState.AUTHORIZATION:
			
				if packet.cmd == FTPCommand.AUTH:
					transport.write(FTPReply(502).toBytes())

				elif packet.cmd == FTPCommand.USER:
					session.User = packet.params[0]
					transport.write(FTPReply(331, 'User name okay, need password.').toBytes())

				elif packet.cmd == FTPCommand.PASS:
					session.Pass = packet.params[0]

					self.logResult(session, {
							'type'     : 'Cleartext', 
							'client'   : session.connection.remote_ip, 
							'user'     : session.User,
							'cleartext': session.Pass, 
							'fullhash' : session.User + ':' + session.Pass
							})

					transport.write(FTPReply(530).toBytes())

				else:
					transport.write(FTPReply(503).toBytes())
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
		self._session = FTPSession(server.rdnsd)

	def _connection_made(self):
		self._server.sendWelcome(self._transport)

	def _data_received(self, raw_data):
		return

	def _connection_lost(self, exc):
		return

	def _parsebuff(self):
		#FTP commands are terminated by new line chars
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
