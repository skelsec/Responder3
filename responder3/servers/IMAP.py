import os
import logging
import traceback
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP, ProtocolSession
from responder3.newpackets.IMAP import *

class IMAPSession(ProtocolSession):
	def __init__(self, server):
		ProtocolSession.__init__(self, server)
		self.encoding     = 'utf-7'
		self.cmdParser    = IMAPCommandParser(encoding = self.encoding)
		self.currentState = IMAPState.NOTAUTHENTICATED
		self.User = None
		self.Pass = None


class IMAP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		self.protocol = IMAPProtocol

	def modulename(self):
		return 'IMAP'

	def sendWelcome(self, transport):
		transport.write(IMAPOKResp(msg ='hello from Honeyport IMAP server').toBytes())

	def handle(self, packet, transport, session):
		try:
			if 'R3DEEPDEBUG' in os.environ:
				self.log(logging.INFO,'Session state: %s Command: %s' % (session.currentState.name, packet.command.name if packet is not None else 'NONE'), session)
				print(repr(packet))

			if session.currentState == IMAPState.NOTAUTHENTICATED:
				if packet.command == IMAPCommand.LOGIN:
					session.User = packet.params[0]
					session.Pass = packet.params[1]
					if self.check_credentials(transport, session):
						session.currentState = IMAPState.AUTHENTICATED
						transport.write(IMAPOKResp(tag=packet.tag, msg='CreZ good!').toBytes())
					else:
						transport.write(IMAPNOResp(tag=packet.tag, msg='wrong credZ!').toBytes())
						transport.close()

					return

				elif packet.command == IMAPCommand.CAPABILITY:
					authMethods = IMAPAuthMethods()
					authMethods.methods.append('PLAIN')
					capabilities = IMAPCapabilities(authMethods)
					capabilities.capabilities.append('IMAP4')
					capabilities.capabilities.append('IMAP4rev1')
					print('ptag: %s' % packet.tag )
					transport.write(IMAPCAPABILITYResp(capabilities=capabilities).toBytes())
					transport.write(IMAPOKResp(tag=packet.tag,msg ='Completed').toBytes())
					return

			else:
				raise Exception('not implemented!')
				transport.close()


		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			transport.close()
			pass

	def check_credentials(self, transport, session):
		self.logResult(session,{
						'type': 'Cleartext', 
						'client'   : session.connection.remote_ip, 
						'user'     : session.User,
						'cleartext': session.Pass, 
						'fullhash' : session.User + ':' + session.Pass
					})
		
		if session.User == 'aaaaaaaaaa' and session.Pass == 'bbbbbbb124234123':
			#login sucsess
			return True

		return False
		

class IMAPProtocol(ResponderProtocolTCP):
	
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)
		self._buffer_maxsize = 1*1024
		self._session = IMAPSession(server.rdnsd)

	def _connection_made(self):
		self._server.sendWelcome(self._transport)

	def _data_received(self, raw_data):
		return

	def _connection_lost(self, exc):
		return

	def _parsebuff(self):
		#IMAP commands are terminated by new line chars
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


class IMAPS(IMAP):
	def modulename(self):
		return 'IMAPS'