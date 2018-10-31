import enum
import logging
import asyncio

from responder3.core.commons import *
from responder3.protocols.TELNET import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class TELNETSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.parser = TELNETMessageParser(self)

	def __repr__(self):
		t = '== TELNET Session ==\r\n'
		return t


class TELNET(ResponderServer):
	def init(self):
		self.banner = ''
		self.username = None
		self.password = None
		
		if self.settings and 'banner' in self.settings:
			self.banner = self.settings['banner']
		
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

	async def parse_message(self, timeout=None):
		try:
			req = await asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout=timeout)
			return req
		except asyncio.TimeoutError:
			await self.log('Timeout!', logging.DEBUG)
			return None
		except ConnectionClosed:
			return None
		except Exception:
			await self.log_exception()
			return None

	async def run(self):
		try:
			#if self.banner:
			#	await self.send_message(self.banner)
				
			#await self.send_data(b'\x00')
			while not self.creader.at_eof():
				data = await self.parse_message()
				if isinstance(data, bytes):
					#extended options list, not handled bc it's a dumb server
					if self.banner:
						await self.send_message(self.banner)
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
					await self.log_credential(cred)
					return
					
				await self.log('Incoming data: %s' % repr(data))
				
				
		except Exception as e:
			await self.log_exception()
			return
