import logging
import traceback
import socket
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP
from responder3.packets import FTPPacket

class FTP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		self.protocol = FTPProtocol
		self.curstate = 0
		self.User = None
		self.Pass = None


	def modulename(self):
		return 'FTP'

	def handle(self, data, transport):
		try:
			self.log(logging.DEBUG,'Handle called with data: ' + str(data))
			if self.curstate == 0:
				#send welcome msg
				transport.write(FTPPacket().getdata())
				self.curstate = 1
				return
			
			elif self.curstate == 1:
				#check if user is sent
				if data[0:4] == "USER":
					self.User = data[5:].strip()

					Packet = FTPPacket(Code=b"331",Message=b"User name okay, need password.")
					transport.write(Packet.getdata())
					self.curstate = 2
					return
				else:
					self.cmderr(transport)

			elif self.curstate == 2:
				#check if password is sent
				if data[0:4] == "PASS":
					self.Pass = data[5:].strip()

					self.logResult({
						'module': self.modulename(), 
						'type': 'Cleartext', 
						'client': self.peername, 
						'user': self.User, 
						'cleartext': self.Pass, 
						'fullhash': self.User + ':' + self.Pass
					})

					Packet = FTPPacket(Code=b"530",Message=b"User not logged in.")
					transport.write(Packet.getdata())
					self.curstate = 3

				else:
					self.cmderr(transport)
				
			else:
				self.cmderr(transport)
	

		except Exception as e:
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			pass

	def cmderr(self, transport):
		Packet = FTPPacket(Code=b"502",Message=b"Command not implemented.")
		transport.write(Packet.getdata())
		transport.close()


class FTPProtocol(ResponderProtocolTCP):
	
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
			self._server.handle(self._buffer[:endpos],self._transport)
			self._buffer = self._buffer[endpos+2:]