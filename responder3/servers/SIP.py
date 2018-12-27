import enum
import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import *
from responder3.core.commons import *
from responder3.protocols.SIP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession
from responder3.protocols.authentication.loader import *


class SIPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.status = SIPSessionStatus.UNAUTHENTICATED
		self.auth_mecha_name, self.auth_mecha  = AuthMechaLoader.from_dict({'auth_mecha':'DIGEST'})

		self.read_cnt = 0

class SIP(ResponderServer):
	def init(self):
		pass

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	@r3trafficlogexception
	async def run(self):
		while not self.shutdown_evt.is_set():
			if self.cproto == 'UDP' and self.session.read_cnt > 0:
				# breaking continue in case of UDP, which can be only read once
				return
			self.session.read_cnt += 1

			try:
				result = await asyncio.gather(*[asyncio.wait_for(Request.from_streamreader(self.creader), timeout=None)], return_exceptions=True)
			except asyncio.CancelledError as e:
				raise e
			if isinstance(result[0], R3ConnectionClosed):
				return
			elif isinstance(result[0], Exception):
				raise result[0]
			else:
				req = result[0]

			if self.session.status == SIPSessionStatus.UNAUTHENTICATED:
				auth_data = None
				if 'authorization' in req.spec_headers:
					auth_line = req.spec_headers['authorization']
					m = auth_line.find(' ')
					if m != -1:
						atype = auth_line[:m]
						auth_data = auth_line[m+1:]

				status, data = self.session.auth_mecha.do_auth(auth_data, method = req.method, body_data = req.data)

				if status == AuthResult.OK or status == AuthResult.FAIL:
					await self.logger.credential(data.to_credential())
				
				if status == AuthResult.OK:
					self.session.status = SIPSessionStatus.AUTHENTICATED
					# TODO: implement this
					# SIP200Resonse
					return
				
				elif status == AuthResult.FAIL:
					self.session.status = SIPSessionStatus.AUTHFAILED
					await self.send_data(SIP403Response().to_bytes())
					return
				
				elif status == AuthResult.CONTINUE:
					rdata = self.session.auth_mecha_name.name
					rdata += ' %s' % data
					
					resp = SIP401Response.from_request(req, rdata)
					data = resp.to_bytes()
					self.cwriter.write(data)
					continue

			else:
				#TODO: continue implementation :)
				return

			return