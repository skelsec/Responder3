import traceback
import logging
import io
import os
import enum
import uuid
from responder3.utils import ServerFunctionality
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP, ProtocolSession
from responder3.protocols.SMB.SMBParser import SMBCommandParser
from responder3.protocols.SMB.SMB import * 
from responder3.protocols.SMB.SMB2 import * 
from responder3.protocols.SMB.ntstatus import * 
from responder3.protocols.GSSAPI import * 

class SMB2ServerState(enum.Enum):
	UNAUTHENTICATED = enum.auto()
	AUTHENTICATED = enum.auto()

class SMBSession(ProtocolSession):
	def __init__(self, server):
		ProtocolSession.__init__(self, server)
		self.cmdParser = SMBCommandParser
		self._buffer_minsize = 4 #netbios session header including the size of the whole message
		self._packet_size = -1
		self.SMBprotocol  = None
		self.SMBdialect   = 'SMB 2.002'
		self.currentState = SMB2ServerState.UNAUTHENTICATED
		self.gssapihandler = GSSAPIAuthHandler()
		self.serverUUID = uuid.UUID(bytes=os.urandom(16))
		self.SMBSessionID = os.urandom(8)
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
			if session.currentState == SMB2ServerState.UNAUTHENTICATED:
				#this could be SMB/NegotiateProtocol or SMB2/NegotiateProtocol or SMB2/SessionSetup
				if msg.type == 1:
					if msg.header.Command == SMBCommand.SMB_COM_NEGOTIATE:
						#currently we only supports smbv2, but the way the protocol is,
						#the first message could be SMBv1/NegotiateProtocol to identiy smbv2
						print([dialect.DialectString for dialect in msg.command.data.Dialects])
						if session.SMBdialect in [dialect.DialectString for dialect in msg.command.data.Dialects]:
							print('client is capable of smbv2')
							status, data, t = session.gssapihandler.do_AUTH()
							resp = SMB2Message()
							resp.header = SMB2Header_ASYNC.construct(SMB2Command.NEGOTIATE, SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR, 0)
							resp.command = NEGOTIATE_REPLY.construct(data, NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
								NegotiateDialects.SMB202, session.serverUUID, NegotiateCapabilities.SMB2_GLOBAL_CAP_DFS|NegotiateCapabilities.SMB2_GLOBAL_CAP_LEASING|NegotiateCapabilities.SMB2_GLOBAL_CAP_LARGE_MTU)

							respdata = resp.toBytes()
							transport.write(b'\x00' + len(respdata).to_bytes(3, byteorder = 'big') + respdata)
						else:
							transport.close()
							raise Exception('client is NOT capable of smbv2')
							
					else:
						raise Exception('SMBv1 currently not supported!')
				else:
					if msg.header.Command == SMB2Command.NEGOTIATE:
						status, data, t = session.gssapihandler.do_AUTH()
						resp = SMB2Message()
						resp.header = SMB2Header_ASYNC.construct(SMB2Command.NEGOTIATE, SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR, 0)
						resp.command = NEGOTIATE_REPLY.construct(data, NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
							NegotiateDialects.SMB202, session.serverUUID, NegotiateCapabilities.SMB2_GLOBAL_CAP_DFS|NegotiateCapabilities.SMB2_GLOBAL_CAP_LEASING|NegotiateCapabilities.SMB2_GLOBAL_CAP_LARGE_MTU)

						respdata = resp.toBytes()
						transport.write(b'\x00' + len(respdata).to_bytes(3, byteorder = 'big') + respdata)
					elif msg.header.Command == SMB2Command.SESSION_SETUP:
						status, data, creds = session.gssapihandler.do_AUTH(msg.command.Buffer)
						if creds is not None:
							if isinstance(creds, list):
								for cred in creds:
									print(cred.toResult())
							else:
								print(creds.toResult())
						
						resp = SMB2Message()
						resp.header = SMB2Header_ASYNC.construct(SMB2Command.SESSION_SETUP, SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR, 1 ,status = NTStatus.STATUS_MORE_PROCESSING_REQUIRED,
							Credit = 1, CreditCharge = 1, SessionId= session.SMBSessionID)
						resp.command = SESSION_SETUP_REPLY.construct(data,0)

						respdata = resp.toBytes()
						transport.write(b'\x00' + len(respdata).to_bytes(3, byteorder = 'big') + respdata)

					else:
						raise Exception('Dunno!')

			if session.currentState == SMB2ServerState.AUTHENTICATED:
				transport.close()
				raise Exception('Dunno what to do now that authentication was sucsessfull')



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
