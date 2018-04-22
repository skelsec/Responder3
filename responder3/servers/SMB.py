import logging
import asyncio
from urllib.parse import urlparse
import uuid
import random
from responder3.core.commons import *
from responder3.protocols.SMB.SMBTransport import SMBTransport
from responder3.protocols.SMB.SMB import * 
from responder3.protocols.SMB.SMB2 import * 
from responder3.protocols.SMB.ntstatus import * 
from responder3.protocols.GSSAPI import * 
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

class SMB2ServerState(enum.Enum):
	UNAUTHENTICATED = enum.auto()
	AUTHENTICATED = enum.auto()

class SMBSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.SMBprotocol  = None
		#self.SMBdialect   = 'SMB 2.002'
		self.SMBdialect   = ['NT LM 0.12']
		self.commondialect = None

		self.current_state = SMB2ServerState.UNAUTHENTICATED
		self.gssapihandler = GSSAPIAuthHandler()
		self.serverUUID = uuid.UUID(bytes=os.urandom(16))
		self.SMBSessionID = os.urandom(8)
		self.SMBMessageCnt = 0
		#self.authAPI      = None


	def __repr__(self):
		t  = '== SMBSession ==\r\n'
		t += 'SMBprotocol:      %s\r\n' % repr(self.HTTPVersion)
		t += 'SMBdialect: %s\r\n' % repr(self.HTTPContentEncoding)
		t += 'commondialect: %s\r\n' % repr(self.HTTPConectentCharset)
		t += 'current_state: %s\r\n' % repr(self.HTTPAtuhentication)
		t += 'gssapihandler:       %s\r\n' % repr(self.HTTPCookie)
		t += 'serverUUID: %s\r\n' % repr(self.HTTPServerBanner)
		t += 'SMBSessionID:     %s\r\n' % repr(self.current_state)
		t += 'SMBMessageCnt:     %s\r\n' % repr(self.current_state)
		return t

class SMB(ResponderServer):
	def init(self):
		self.parser = SMBTransport
		self.parse_settings()
		

	def parse_settings(self):
		pass
		"""
		if self.settings is None:
			#default settings, basically just NTLM auth
			self.session.isproxy = True
			
			#self.session.HTTPAtuhentication   = HTTPNTLMAuth(isProxy = self.session.isproxy)
			#self.session.HTTPAtuhentication.setup()
			self.session.HTTPAtuhentication  = HTTPBasicAuth(isProxy = self.session.isproxy)
			
			
		else:
			if 'authentication' in self.settings:
				#supported authentication mechanisms
				if self.settings['authentication']['authmecha'].upper() == 'NTLM':
					self.session.HTTPAtuhentication   = HTTPNTLMAuth(isProxy = self.session.isproxy)
					if 'settings' in self.settings['authentication']:
						self.session.HTTPAtuhentication.setup(self.settings['authentication']['settings'])
				
				elif self.settings['authmecha'].upper() == 'BASIC':
					self.session.HTTPAtuhentication  = HTTPBasicAuth(isProxy = self.session.isproxy)

				else:
					raise Exception('Unsupported HTTP authentication mechanism: %s' % (self.settings['authentication']['authmecha']))

				if 'cerdentials' in self.settings['authentication']:
					self.session.HTTPAtuhentication.verifyCreds = self.settings['authentication']['cerdentials']
		"""



	async def parse_message(self, timeout = 10):
		try:
			smbtransport = await asyncio.wait_for(self.parser.from_streamreader(self.creader), timeout = timeout)
			return smbtransport.smbmessage
		except asyncio.TimeoutError:
			await self.log('Timeout!', logging.DEBUG)

	async def send_data(self, smbmessage):
		data = self.parser.construct(smbmessage)
		self.cwriter.write(data.toBytes())
		await self.cwriter.drain()

	async def send_authfailed(self, smbmessage):
		return

	async def run(self):
		try:
			while True:
				msg = await asyncio.wait_for(self.parse_message(None), timeout = None)
				if self.session.current_state == SMB2ServerState.UNAUTHENTICATED:
					#this could be SMB/NegotiateProtocol or SMB2/NegotiateProtocol or SMB2/SessionSetup
					if msg.type == 1:
						if msg.header.Command == SMBCommand.SMB_COM_NEGOTIATE:
							#the first message could be SMBv1/NegotiateProtocol to identiy smbv2 capabilities
							await self.log([dialect.DialectString for dialect in msg.command.Dialects], logging.DEBUG)
							#selecting the dialect which is common to both server and client in order of server dialect list prefereances
							clinet_dialects = set([dialect.DialectString for dialect in msg.command.Dialects])
							server_dialects = set(self.session.SMBdialect)
							common_dialects = server_dialects.intersection(clinet_dialects)
							if common_dialects is None:
								await self.log('No matching dialects between client and server, terminating connection!')
								return
							preferred_dialect = None
							for dialect in self.session.SMBdialect:
								for cd in common_dialects:
									if cd == dialect:
										preferred_dialect = dialect
										break
								else:
									continue
								break
							#now, for smbv1 we need to get the index of the selected dialect... 
							preferred_dialect_idx = 0
							for dialect in [dialect.DialectString for dialect in msg.command.Dialects]:
								if dialect == preferred_dialect:
									#preferred_dialect_idx += 1
									break
								preferred_dialect_idx += 1

							await self.log(preferred_dialect_idx, logging.INFO)

							self.session.commondialect = preferred_dialect

							if self.session.commondialect == 'SMB 2.002':
								await self.log('client is capable of smbv2, using SMBv2', logging.DEBUG)
								status, data, t = self.session.gssapihandler.do_AUTH()
								resp = SMB2Message()
								resp.header = SMB2Header_ASYNC.construct(SMB2Command.NEGOTIATE, SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR, self.SMBMessageCnt)
								resp.command = NEGOTIATE_REPLY.construct(data, NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
									NegotiateDialects.SMB202, self.session.serverUUID, NegotiateCapabilities.SMB2_GLOBAL_CAP_DFS|NegotiateCapabilities.SMB2_GLOBAL_CAP_LEASING|NegotiateCapabilities.SMB2_GLOBAL_CAP_LARGE_MTU)

								#MessageCn t should not be incremented here
								a = await asyncio.wait_for(self.send_data(resp), timeout=1)
							
							else:
								await self.log('using SMBv1', logging.DEBUG)
								status, data, t = self.session.gssapihandler.do_AUTH(smbv1 = True)
								resp = SMBMessage()
								resp.header = SMBHeader.construct(SMBCommand.SMB_COM_NEGOTIATE, 
																	NTStatus.STATUS_SUCCESS, 
																	
																	SMBHeaderFlagsEnum.SMB_FLAGS_REPLY|
																	SMBHeaderFlagsEnum.SMB_FLAGS_CASE_INSENSITIVE, 
																	SMBHeaderFlags2Enum.SMB_FLAGS2_UNICODE|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_EXTENDED_SECURITY|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_NT_STATUS|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_LONG_NAMES,
																	mid = msg.header.MID,
																	pidhigh = msg.header.PIDHigh,
																	pidlow = msg.header.PIDLow,
																)
																	

								resp.command = SMB_COM_NEGOTIATE_REPLY.construct(preferred_dialect_idx, 
																SMBSecurityMode.NEGOTIATE_ENCRYPT_PASSWORDS|SMBSecurityMode.NEGOTIATE_USER_SECURITY, 
																b'\x00'*4, 
																SMBCapabilities.CAP_UNICODE|SMBCapabilities.CAP_NT_SMBS|SMBCapabilities.CAP_LARGE_FILES|SMBCapabilities.CAP_NT_EXTENDED_SECURITY, 
																self.session.serverUUID, data,
															)

								a = await asyncio.wait_for(self.send_data(resp), timeout=1)
								continue
						else:
							if msg.header.Command == SMBCommand.SMB_COM_SESSION_SETUP_ANDX:
								status, data, creds = self.session.gssapihandler.do_AUTH(msg.command.SecurityBlob)
								
								if status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED:
									resp.header = SMBHeader.construct(SMBCommand.SMB_COM_SESSION_SETUP_ANDX, 
																	NTStatus.STATUS_MORE_PROCESSING_REQUIRED, 
																	
																	SMBHeaderFlagsEnum.SMB_FLAGS_REPLY|
																	SMBHeaderFlagsEnum.SMB_FLAGS_CASE_INSENSITIVE, 
																	SMBHeaderFlags2Enum.SMB_FLAGS2_UNICODE|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_EXTENDED_SECURITY|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_NT_STATUS|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_LONG_NAMES,
																	uid = random.randint(1,5000),
																	mid = msg.header.MID,
																	pidhigh = msg.header.PIDHigh,
																	pidlow = msg.header.PIDLow,
																)
									resp.command = SMB_COM_SESSION_SETUP_ANDX_REPLY.construct(secblob = data, 
																							  nativeos = 'Windows 2003', 
																							  nativelanman = 'blabla'
																							)
									a = await asyncio.wait_for(self.send_data(resp), timeout=1)
									continue

								elif status == NTStatus.STATUS_ACCOUNT_DISABLED:
									if creds is not None:
										for cred in creds:
											await self.log_credential(cred.toCredential())
									
									resp.header = SMBHeader.construct(SMBCommand.SMB_COM_SESSION_SETUP_ANDX, 
																	NTStatus.STATUS_ACCOUNT_DISABLED, 
																	
																	SMBHeaderFlagsEnum.SMB_FLAGS_REPLY|
																	SMBHeaderFlagsEnum.SMB_FLAGS_CASE_INSENSITIVE, 
																	SMBHeaderFlags2Enum.SMB_FLAGS2_UNICODE|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_EXTENDED_SECURITY|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_NT_STATUS|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_LONG_NAMES,
																	uid = msg.header.UID,
																	mid = msg.header.MID,
																	pidhigh = msg.header.PIDHigh,
																	pidlow = msg.header.PIDLow,
																)
									resp.command = SMB_COM_SESSION_SETUP_ANDX_REPLY.construct(secblob = data, 
																							  nativeos = 'Windows 2003', 
																							  nativelanman = 'blabla'
																							)
									a = await asyncio.wait_for(self.send_data(resp), timeout=1)
									continue
								
								elif status == NTStatus.STATUS_SUCCESS:
									if creds is not None:
										for cred in creds:
											await self.log_credential(cred.toCredential())
									self.session.current_state = SMB2ServerState.AUTHENTICATED
									resp.header = SMBHeader.construct(SMBCommand.SMB_COM_SESSION_SETUP_ANDX, 
																	NTStatus.STATUS_SUCCESS, 
																	
																	SMBHeaderFlagsEnum.SMB_FLAGS_REPLY|
																	SMBHeaderFlagsEnum.SMB_FLAGS_CASE_INSENSITIVE, 
																	SMBHeaderFlags2Enum.SMB_FLAGS2_UNICODE|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_EXTENDED_SECURITY|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_NT_STATUS|
																	SMBHeaderFlags2Enum.SMB_FLAGS2_LONG_NAMES,
																	uid = msg.header.UID,
																	mid = msg.header.MID,
																	pidhigh = msg.header.PIDHigh,
																	pidlow = msg.header.PIDLow,
																)
									resp.command = SMB_COM_SESSION_SETUP_ANDX_REPLY.construct(secblob = data, 
																							  nativeos = 'Windows 2003', 
																							  nativelanman = 'blabla'
																							)

								
							else:
								raise Exception('not implemented!')

					
					else:
						if msg.header.Command == SMB2Command.NEGOTIATE:
							status, data, t = self.session.gssapihandler.do_AUTH()
							resp = SMB2Message()
							resp.header = SMB2Header_ASYNC.construct(SMB2Command.NEGOTIATE, SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR, self.SMBMessageCnt)
							resp.command = NEGOTIATE_REPLY.construct(data, NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
								NegotiateDialects.SMB202, self.session.serverUUID, NegotiateCapabilities.SMB2_GLOBAL_CAP_DFS|NegotiateCapabilities.SMB2_GLOBAL_CAP_LEASING|NegotiateCapabilities.SMB2_GLOBAL_CAP_LARGE_MTU)

							a = await asyncio.wait_for(send_data(resp), timeout=1)
						
						elif msg.header.Command == SMB2Command.SESSION_SETUP:
							status, data, creds = self.session.gssapihandler.do_AUTH(msg.command.Buffer)
							if creds is not None:
								for cred in creds:
									await self.log_credential(cred.toCredential())
								return
							
							resp = SMB2Message()
							resp.header = SMB2Header_ASYNC.construct(SMB2Command.SESSION_SETUP, SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR, 1 ,status = NTStatus.STATUS_MORE_PROCESSING_REQUIRED,
								Credit = 1, CreditCharge = 1, SessionId= self.session.SMBSessionID)
							resp.command = SESSION_SETUP_REPLY.construct(data,0)

							a = await asyncio.wait_for(self.send_data(resp), timeout=1)
						else:
							raise Exception('Dunno!')

				if self.session.current_state == SMB2ServerState.AUTHENTICATED:
					raise Exception('Dunno what to do now that authentication was sucsessfull')


		except Exception as e:
			await self.log_exception()
			return