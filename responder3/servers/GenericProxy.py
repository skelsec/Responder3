import logging
import asyncio
from responder3.core.commons import *
from responder3.core.udpwrapper import UDPClient
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


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
		
		

	@asyncio.coroutine
	def parse_message(self):
		return self.creader.read(1024)

	@asyncio.coroutine
	def send_banner(self):
		pass

	@asyncio.coroutine
	def send_data(self, data):
		self.cwriter.write(data)
		yield from self.cwriter.drain()

	@asyncio.coroutine
	def generic_read(self, reader):
		return reader.read(1024)

	@asyncio.coroutine
	def modify_data(self, data):
		return data

	@asyncio.coroutine
	def proxy_forwarder(self, reader, writer, laddr, raddr):
		while not self.proxy_closed.is_set():
			try:
				data = yield from asyncio.wait_for(self.generic_read(reader), timeout=self.timeout)
			except asyncio.TimeoutError:
				self.log('Timeout!', logging.DEBUG)
				self.proxy_closed.set()
				break	
			
			if data == b'' or reader.at_eof():
				print('Connection closed!')
				self.proxy_closed.set()
				break
			

			self.logProxy('original data: %s' % data.hex(), laddr, raddr)
			self.logProxyData(data, laddr, raddr, False, ProxyDataType.BINARY)
			modified_data = yield from self.modify_data(data)
			if modified_data != data:
				self.logProxy('modified data: %s' % repr(modified_data),laddr, raddr)
			
			try:
				writer.write(modified_data)
				yield from asyncio.wait_for(writer.drain(), timeout=self.timeout)
			except asyncio.TimeoutError:
				self.log('Timeout!', logging.DEBUG)
				self.proxy_closed.set()
				break

		return

	@asyncio.coroutine
	def udp_proxy(self):
		laddr = (self.creader._addr[0], self.creader._addr[1])
		raddr = (self.remote_host, self.remote_port)
		data = yield from self.creader.read()
		
		self.logProxy('original data: %s' % repr(data), laddr, raddr)
		
		client = UDPClient((self.remote_host, self.remote_port))
		self.proxy_reader, self.proxy_writer = yield from asyncio.wait_for(client.run(data), timeout=self.timeout)
		
		response_data = yield from self.proxy_reader.read()
		
		self.logProxy('original data: %s' % repr(response_data), raddr, laddr)
		yield from self.cwriter.write(response_data)
		return

	@asyncio.coroutine
	def run(self):
		self.log('Starting task!', logging.DEBUG)
		self.log('Setting up remote connection!', logging.DEBUG)
		loop = asyncio.get_event_loop()
		
		if self.sprops.bind_porotcol in [ServerProtocol.TCP,ServerProtocol.SSL]:
			self.proxy_reader, self.proxy_writer = yield from asyncio.wait_for(asyncio.open_connection(host=self.remote_host,port = self.remote_port, ssl=self.proxy_sslctx), timeout=self.timeout)
			self.log('Connected!', logging.DEBUG)
			loop.create_task(self.proxy_forwarder(self.proxy_reader, self.cwriter, (self.remote_host,int(self.remote_port)), self.caddr))
			loop.create_task(self.proxy_forwarder(self.creader, self.proxy_writer, self.caddr, (self.remote_host,int(self.remote_port))))
			
			yield from asyncio.wait_for(self.proxy_closed.wait(), timeout = None)

		else:
			loop.create_task(self.udp_proxy())

		