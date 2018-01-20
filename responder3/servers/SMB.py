import traceback
import logging
import io
import os
from responder3.utils import ServerFunctionality
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP, ProtocolSession
from responder3.newpackets.SMB.SMBParser import SMBCommandParser


class SMBSession(ProtocolSession):
	def __init__(self, server):
		ProtocolSession.__init__(self, server)
		self.cmdParser = SMBCommandParser
		self._buffer_minsize = 4 #netbios session header including the size of the whole message
		self._packet_size = -1
		self.SMBprotocol  = None
		self.SMBdialect   = None
		#self.currentState = SMTPServerState.START
		#self.authAPI      = None

class SMB(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)

	def setup(self):
		self.protocol = SMBProtocol

	def modulename(self):
		return 'SMB'

	def handle(self, msg, transport, session):
		if 'R3DEEPDEBUG' in os.environ:
			self.log(logging.INFO,'Message: %s' % (repr(msg)), session)
		try:
			return
		except Exception as e:
			self.log(logging.INFO,'Exception! %s' % (str(e),), session)
			traceback.print_exc()
			return

class SMBProtocol(ResponderProtocolTCP):
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)
		self._buffer_maxsize = 1*1024
		self._session = SMBSession(server.rdnsd)
	
	def _parsebuff(self):
		try:
			if self._session._packet_size == -1:
				if len(self._buffer) <= self._session._buffer_minsize:
					self._server.log(logging.DEBUG, 'Need moar data!!!')
					return

				if len(self._buffer) > self._session._buffer_minsize:
					assert self._buffer[0] == 0, "This is not SMB data"
					self._session._packet_size = int.from_bytes(self._buffer[1:4], byteorder='big', signed = False) + 4

			if len(self._buffer) >= self._session._packet_size:
				message = self._session.cmdParser.from_bytes(self._buffer[4:self._session._packet_size])
				self._server.handle(message, self._transport, self._session)
				self._buffer = self._buffer[self._session._packet_size:]
				self._session._packet_size = -1
				if len(self._buffer) > self._session._buffer_minsize:
					self._parsebuff()
				
				return			

		except Exception as e:
			self._server.log(logging.INFO,'Exception! %s' % (str(e),))
			traceback.print_exc()
