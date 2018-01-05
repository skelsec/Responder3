import logging
import traceback
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP
from responder3.packets import IMAPGreeting, IMAPCapability, IMAPCapabilityEnd

class IMAP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		self.protocol = IMAPProtocol
		self.curstate = 0
		self.User = None
		self.Pass = None


	def modulename(self):
		return 'IMAP'

	def handle(self, data, transport):
		try:
			self.log(logging.DEBUG,'Handle called with data: ' + str(data))

			if self.curstate == 0:
				#send welcome msg
				transport.write(IMAPGreeting().getdata())
				self.curstate = 1
				return
			
			elif self.curstate == 1:
				#check if user is sent
				tag, cmd, *values = data.split()
				if cmd == "CAPABILITY":
					transport.write(IMAPCapability().getdata())
					transport.write(IMAPCapabilityEnd(Tag=tag.encode()).getdata())
					return


				elif cmd == "LOGIN":
					self.User = values[0]
					self.Pass = values[1]

					self.logResult({
						'module': self.modulename(), 
						'type': 'Cleartext', 
						'client': self.peername, 
						'user': self.User, 
						'cleartext': self.Pass, 
						'fullhash': self.User + ':' + self.Pass
					})

				else:
					self.cmderr(transport)
			else:
				self.cmderr(transport)


		except Exception as e:
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			transport.close()
			pass

	def cmderr(self, transport):
		transport.close()


class IMAPProtocol(ResponderProtocolTCP):
	
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


class IMAPS(IMAP):
	def modulename(self):
		return 'IMAPS'