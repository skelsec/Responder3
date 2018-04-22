import logging
import asyncio

from responder3.core.commons import ProxyDataType
from responder3.core.udpwrapper import UDPClient
from responder3.core.servertemplate import ResponderServer, ResponderServerSession
from responder3.core.asyncio_helpers import *
from responder3.core.ssl import *
from responder3.core.sockets import *


class GenericProxySession(ResponderServerSession):
	pass


class GenericProxy(ResponderServer):
	def init(self):
		self.proxy_reader = None
		self.proxy_writer = None
		self.proxy_closed = asyncio.Event()
		self.proxy_sslctx = None

		#defaults
		self.timeout = None
		self.read_size = 65536
		#parse settings
		if self.settings is None:
			raise Exception('settings MUST be defined!')
		if 'remote_host' not in self.settings:
			raise Exception('remote_host MUST be defined!')
		if 'remote_port' not in self.settings:
			raise Exception('remote_port MUST be defined!')

		if 'remote_sslctx' in self.settings:
			self.proxy_sslctx = SSLContextBuilder.from_dict(self.settings['remote_sslctx'])
	
		if 'timeout' in self.settings:
			self.timeout = int(self.settings['timeout'])
			if self.timeout == -1:
				self.timeout = None

		self.remote_host = self.settings['remote_host']
		self.remote_port = int(self.settings['remote_port'])

	async def modify_data(self, data):
		return data

	async def proxy_forwarder(self, reader, writer, laddr, raddr):
		while not self.proxy_closed.is_set():
			try:
				data = await asyncio.wait_for(generic_read(reader, self.read_size), timeout=self.timeout)
			except asyncio.TimeoutError:
				await self.log('Timeout!', logging.DEBUG)
				self.proxy_closed.set()
				break	
			
			if data == b'' or reader.at_eof():
				print('Connection closed!')
				self.proxy_closed.set()
				break

			await self.log_proxy('original data: %s' % data.hex(), laddr, raddr)
			await self.log_proxydata(data, laddr, raddr, False, ProxyDataType.BINARY)
			modified_data = await self.modify_data(data)
			if modified_data != data:
				await self.log_proxy('modified data: %s' % repr(modified_data), laddr, raddr)
			
			try:
				await asyncio.wait_for(generic_write(writer, modified_data), timeout=self.timeout)
			except asyncio.TimeoutError:
				await self.log('Timeout!', logging.DEBUG)
				self.proxy_closed.set()
				break

		return

	async def udp_proxy(self):
		laddr = (self.creader._addr[0], self.creader._addr[1])
		raddr = (self.remote_host, self.remote_port)
		data = await self.creader.read()
		
		await self.log_proxy('original data: %s' % repr(data), laddr, raddr)
		
		client = UDPClient((self.remote_host, self.remote_port))
		self.proxy_reader, self.proxy_writer = await asyncio.wait_for(client.run(data), timeout=self.timeout)
		
		response_data = await self.proxy_reader.read()
		
		await self.log_proxy('original data: %s' % repr(response_data), raddr, laddr)
		await self.cwriter.write(response_data)
		return

	async def run(self):
		await self.log('Starting task!', logging.DEBUG)
		await self.log('Setting up remote connection!', logging.DEBUG)
		loop = asyncio.get_event_loop()
		
		if self.listener_socket_config.bind_protocol == socket.SOCK_STREAM:
			self.proxy_reader, self.proxy_writer = await asyncio.wait_for(asyncio.open_connection(host=self.remote_host,port = self.remote_port, ssl=self.proxy_sslctx), timeout=self.timeout)
			await self.log('Connected!', logging.DEBUG)
			loop.create_task(self.proxy_forwarder(self.proxy_reader, self.cwriter, (self.remote_host,int(self.remote_port)), self.caddr))
			loop.create_task(self.proxy_forwarder(self.creader, self.proxy_writer, self.caddr, (self.remote_host,int(self.remote_port))))
			
			await self.proxy_closed.wait()

		else:
			loop.create_task(self.udp_proxy())
