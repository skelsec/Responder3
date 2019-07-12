#TODO: not yet supporting the new framework!!!
import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.logging.log_objects import ProxyDataType
from responder3.core.udpwrapper import UDPClient
from responder3.core.servertemplate import ResponderServer, ResponderServerSession
from responder3.core.asyncio_helpers import *
from responder3.core.ssl import *
from responder3.core.sockets import *


class GenericProxySession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)


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

	@r3trafficlogexception
	async def proxy_forwarder(self, reader, writer, laddr, raddr):
		while not self.proxy_closed.is_set():
			try:
				data = await asyncio.wait_for(reader.read(self.read_size), timeout=self.timeout)
				print(data)
			except asyncio.TimeoutError:
				await self.logger.debug('Timeout!')
				self.proxy_closed.set()
				writer.close()
				break
			except Exception as e:
				await self.logger.error('proxy_forwarder exception: %s' % e)
				self.proxy_closed.set()
				writer.close()
				break
				
			
			if data == b'' or reader.at_eof():
				print('Connection closed!')
				self.proxy_closed.set()
				break

			await self.logger.proxy(data, laddr, raddr)
			await self.logger.proxydata(data, laddr, raddr, self.proxy_sslctx is None, ProxyDataType.BINARY)
			modified_data = await self.modify_data(data)
			if modified_data != data:
				await self.logger.proxy(data, laddr, raddr)
			
			try:
				writer.write(modified_data)
				await asyncio.wait_for(writer.drain(), timeout=self.timeout)
			except asyncio.TimeoutError:
				await self.logger.debug('Timeout!')
				self.proxy_closed.set()
				writer.close()
				break
			except Exception as e:
				await self.logger.error('proxy_forwarder 2 exception: %s' % e)
				self.proxy_closed.set()
				writer.close()
				break

		return
	
	@r3trafficlogexception
	async def udp_proxy(self):
		laddr = (self.creader._addr[0], self.creader._addr[1])
		raddr = (self.remote_host, self.remote_port)
		data = await self.creader.read()
		
		await self.logger.proxy(data, laddr, raddr)
		
		client = UDPClient((self.remote_host, self.remote_port))
		self.proxy_reader, self.proxy_writer = await asyncio.wait_for(client.run(data), timeout=self.timeout)
		
		response_data = await self.proxy_reader.read()
		
		await self.logger.proxy(data, raddr, laddr)
		self.cwriter.write(response_data)
		return
	
	@r3trafficlogexception
	async def run(self):
		await self.logger.debug('Starting task!')
		await self.logger.debug('Setting up remote connection!')
		loop = asyncio.get_event_loop()
		
		if self.listener_socket_config.bind_protocol == socket.SOCK_STREAM:
			self.proxy_reader, self.proxy_writer = await asyncio.wait_for(asyncio.open_connection(host=self.remote_host,port = self.remote_port, ssl=self.proxy_sslctx), timeout=self.timeout)
			await self.logger.debug('Connected!')
			asyncio.ensure_future(self.proxy_forwarder(self.proxy_reader, self.cwriter, (self.remote_host,int(self.remote_port)), self.caddr))
			asyncio.ensure_future(self.proxy_forwarder(self.creader, self.proxy_writer, self.caddr, (self.remote_host,int(self.remote_port))))
			
			await self.proxy_closed.wait()

		else:
			loop.create_task(self.udp_proxy())
