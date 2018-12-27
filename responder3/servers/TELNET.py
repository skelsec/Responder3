import enum
import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.TELNET import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class TELNETSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.parser = TELNETMessageParser(self)
		self.banner = None

	def __repr__(self):
		t = '== TELNET Session ==\r\n'
		return t


class TELNET(ResponderServer):
	def init(self):
		if self.settings:
			self.parse_settings()
			return
		self.set_default_settings()

	def set_default_settings(self):
		self.session.banner = ''

	def parse_settings(self):
		if 'banner' in self.settings:
			self.session.banner = self.settings['banner']
		
	async def send_data(self, data, timeout = None):
		self.cwriter.write(data) # data must be bytes
		await self.cwriter.drain()
		
	async def send_message(self, data, timeout = None): 
		"""
		Sends actual ascii data to client
		MUST NOT contain the end of line char!
		"""
		self.cwriter.write((data + '\r\n').encode())
		await self.cwriter.drain()

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
				data = result[0]

			if isinstance(data, bytes):
				#extended options list, not handled bc it's a dumb server
				if self.session.banner:
					await self.send_message(self.session.banner)
				await self.send_message('Username: ')
				continue
			if not self.username:
				self.username = data
				await self.send_message('Password: ')
				continue
			if not self.password:
				self.password = data
				cred = Credential('TELNET',
						username = self.username,
						password = self.password,
						fullhash='%s:%s' % (self.username, self.password)
					)
				await self.logger.credential(cred)
				return
					
			#await self.logger.debug('Incoming data: %s' % repr(data))
