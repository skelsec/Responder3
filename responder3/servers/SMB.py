import logging
import asyncio
from urllib.parse import urlparse
import uuid
import random
from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import *
from responder3.core.commons import *
from responder3.protocols.SMB.SMBTransport import SMBTransport
from responder3.protocols.SMB.SMB import * 
from responder3.protocols.SMB.SMB2 import * 
from responder3.protocols.SMB.ntstatus import * 
from responder3.protocols.authentication.GSSAPI import * 
from responder3.protocols.authentication.common import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

class SMB2ServerState(enum.Enum):
	UNAUTHENTICATED = enum.auto()
	AUTHENTICATED = enum.auto()

class SMBSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)

		self.parser = SMBTransport
		self.SMBprotocol  = None
		#self.SMBdialect   = 'SMB 2.002'
		self.SMBdialect   = ['SMB 2.002', 'NT LM 0.12', ]
		self.commondialect = None

		self.current_state = SMB2ServerState.UNAUTHENTICATED
		self.gssapihandler = GSSAPIAuthHandler()
		self.serverUUID = uuid.UUID(bytes=os.urandom(16))
		self.SMBSessionID = os.urandom(8)
		self.SMBMessageCnt = 0
		#self.authAPI      = None


	def __repr__(self):
		t  = '== SMBSession ==\r\n'
		t += 'SMBprotocol:      %s\r\n' % repr(self.SMBprotocol)
		t += 'SMBdialect: %s\r\n' % repr(self.SMBdialect)
		t += 'commondialect: %s\r\n' % repr(self.commondialect)
		t += 'current_state: %s\r\n' % repr(self.current_state)
		t += 'gssapihandler:       %s\r\n' % repr(self.gssapihandler)
		t += 'serverUUID: %s\r\n' % repr(self.serverUUID)
		t += 'SMBSessionID:     %s\r\n' % repr(self.SMBSessionID)
		t += 'SMBMessageCnt:     %s\r\n' % repr(self.SMBMessageCnt)
		return t


class SMB(ResponderServer):
	def init(self):
		if self.settings:
			self.parse_settings()
			return
		self.set_default_settings()

	def set_default_settings(self):
		return

	def parse_settings(self):
		#TODO
		self.set_default_settings()



	async def parse_message(self, timeout = 10):
		try:
			smbtransport = await asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout = timeout)
			return smbtransport.smbmessage
		except asyncio.TimeoutError:
			await self.log('Timeout!', logging.DEBUG)

	async def send_data(self, smbmessage):
		data = self.session.parser.construct(smbmessage)
		self.cwriter.write(data.to_bytes())
		await self.cwriter.drain()

	async def send_authfailed(self, smbmessage):
		return

	@r3trafficlogexception
	async def run(self):
		# main loop
		while not self.shutdown_evt.is_set():
			try:
				result = await asyncio.gather(*[asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout=None)], return_exceptions=True)
			except asyncio.CancelledError as e:
				raise e
			if isinstance(result[0], R3ConnectionClosed):
				return
			elif isinstance(result[0], Exception):
				raise result[0]
			else:
				msg = result[0].smbmessage

			if self.session.current_state == SMB2ServerState.UNAUTHENTICATED:
				#this could be SMB/NegotiateProtocol or SMB2/NegotiateProtocol or SMB2/SessionSetup
				if msg.type == 1:
					if msg.header.Command == SMBCommand.SMB_COM_NEGOTIATE:
						#the first message could be SMBv1/NegotiateProtocol to identiy smbv2 capabilities
						await self.logger.debug([dialect.DialectString for dialect in msg.command.Dialects])
						#selecting the dialect which is common to both server and client in order of server dialect list prefereances
						clinet_dialects = set([dialect.DialectString for dialect in msg.command.Dialects])
						server_dialects = set(self.session.SMBdialect)
						common_dialects = server_dialects.intersection(clinet_dialects)
						if common_dialects is None:
							await self.logger.info('No matching dialects between client and server, terminating connection!')
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

						await self.logger.info(preferred_dialect_idx)

						self.session.commondialect = preferred_dialect

						if self.session.commondialect == 'SMB 2.002':
							await self.logger.debug('client is capable of smbv2, using SMBv2')
							status, data, t = self.session.gssapihandler.do_auth()
							resp = SMB2Message()
							resp.header = SMB2Header_ASYNC.construct(SMB2Command.NEGOTIATE, SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR, self.session.SMBMessageCnt)
							resp.command = NEGOTIATE_REPLY.construct(data, NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
								NegotiateDialects.SMB202, self.session.serverUUID, NegotiateCapabilities.SMB2_GLOBAL_CAP_DFS|NegotiateCapabilities.SMB2_GLOBAL_CAP_LEASING|NegotiateCapabilities.SMB2_GLOBAL_CAP_LARGE_MTU)

							# MessageCnt should not be incremented here
							a = await asyncio.wait_for(self.send_data(resp), timeout=1)
							
						else:
							await self.logger.debug('using SMBv1')
							status, data, t = self.session.gssapihandler.do_auth(smbv1 = True)
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
							status, data, cred = self.session.gssapihandler.do_auth(msg.command.SecurityBlob)

							if status in [AuthResult.FAIL, AuthResult.OK]:
								await self.logger.credential(cred.to_credential())

								
							if status == AuthResult.CONTINUE:
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

							elif status == AuthResult.FAIL:							
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
								return
							
							elif status == AuthResult.OK:
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
								resp.command = SMB_COM_SESSION_SETUP_ANDX_REPLY.construct(
									secblob = data,
									nativeos = 'Windows 2003',
									nativelanman = 'blabla'
								)
								a = await asyncio.wait_for(self.send_data(resp), timeout=1)
								continue

								
						else:
							raise Exception('not implemented!')

					
				else:
					if msg.header.Command == SMB2Command.NEGOTIATE:
						status, data, t = self.session.gssapihandler.do_auth()
						resp = SMB2Message()
						resp.header = SMB2Header_ASYNC.construct(SMB2Command.NEGOTIATE, SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR, self.session.SMBMessageCnt)
						resp.command = NEGOTIATE_REPLY.construct(data, NegotiateSecurityMode.SMB2_NEGOTIATE_SIGNING_ENABLED,
							NegotiateDialects.SMB202, self.session.serverUUID, 
							NegotiateCapabilities.SMB2_GLOBAL_CAP_DFS|NegotiateCapabilities.SMB2_GLOBAL_CAP_LEASING|NegotiateCapabilities.SMB2_GLOBAL_CAP_LARGE_MTU
							)

						a = await asyncio.wait_for(self.send_data(resp), timeout=1)
					
					elif msg.header.Command == SMB2Command.SESSION_SETUP:
						status, data, cred = self.session.gssapihandler.do_auth(msg.command.Buffer)
						if cred is not None:
							await self.logger.credential(cred.to_credential())
							
						resp = SMB2Message()
						resp.header = SMB2Header_ASYNC.construct(SMB2Command.SESSION_SETUP, SMB2HeaderFlag.SMB2_FLAGS_SERVER_TO_REDIR, 1 ,status = NTStatus.STATUS_MORE_PROCESSING_REQUIRED,
							Credit = 1, CreditCharge = 1, SessionId= self.session.SMBSessionID)
						resp.command = SESSION_SETUP_REPLY.construct(data,0)

						a = await asyncio.wait_for(self.send_data(resp), timeout=1)
					else:
						raise Exception('Dunno!')

			if self.session.current_state == SMB2ServerState.AUTHENTICATED:
				raise Exception('Dunno what to do now that authentication was sucsessfull')

