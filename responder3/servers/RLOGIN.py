import enum
import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.RLOGIN import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession




class RLOGINSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.current_state = RloginSessionState.BEFORE_AUTH

class RLOGIN(ResponderServer):
	def init(self):
		pass

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	@r3trafficlogexception
	async def run(self):
		# main loop
		while not self.shutdown_evt.is_set():
			if self.session.current_state == RloginSessionState.BEFORE_AUTH:
				try:
					result = await asyncio.gather(*[AuthenticationMessage.from_streamreader(self.creader, timeout=None)], return_exceptions=True)

				except asyncio.CancelledError as e:
					raise e
				if isinstance(result[0], R3ConnectionClosed):
					return
				elif isinstance(result[0], Exception):
					raise result[0]
				else:
					auth_msg = result[0]

				await self.logger.credential(auth_msg.to_credential())

				#no authenticator for now
				return

				# In case of succsess, send a null byte and set current_state
				#self.session.current_state = RloginSessionState.AUTHENTICATED
				#await self.send_data(b'\x00')
			
			elif self.session.current_state == RloginSessionState.AUTHENTICATED:
				#raise NotImplementedError
				return
			else:
				raise Exception('Unknown RLOGIN state!')
