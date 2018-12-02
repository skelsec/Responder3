import enum
import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import *
from responder3.core.commons import *
from responder3.protocols.SIP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class SIPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)


class SIP(ResponderServer):
	def init(self):
		pass

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	@r3trafficlogexception
	async def run(self):
		while not self.shutdown_evt.is_set():
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

			if req.method.upper() == 'REGISTER':
				if 'authorization' in req.spec_headers:
					cred = req.get_sip_hash()
					print(cred)
				else:
					resp = SIP401Response.from_request(req, 'Digest realm="sip.cybercity.dk",nonce="1701af566be182070084c6f740706bb",opaque="1701a1351f70795",stale=false,algorithm=MD5')
					data = resp.to_bytes()
					self.cwriter.write(data)

			return