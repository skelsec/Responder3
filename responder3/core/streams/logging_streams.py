import datetime
import asyncio

from responder3.core.logging.log_objects import * 

class StreamReaderLogging:
	def __init__(self, reader):
		self.reader = reader
		self.traffic = TrafficLog()
		self.last_activity = datetime.datetime.utcnow()

	async def log_comms(self):
		try:
			#data = await asyncio.wait_for(self.reader.read(-1), timeout = 1)
			data = await asyncio.gather(*[asyncio.wait_for(self.reader.read(-1), timeout = 1)], return_exceptions=True)
		except Exception as e:
			print('Error: %s' % str(e))
			#the error here that sometime despite cancelling the reading task
			#the task is still waiting for incoming data, which is strange
			pass
		else:
			if isinstance(data, bytes):
				self.traffic.unconsumed_buffer = data[0]
				
		return self.traffic


	async def read(self, n=-1):
		data = await self.reader.read(n=n)
		if not data:
			return data
		self.traffic.data_recv[datetime.datetime.utcnow()] = data
		self.last_activity = datetime.datetime.utcnow()
		return data

	async def readexactly(self, n):
		data = await self.reader.readexactly(n)
		if not data:
			return data
		self.traffic.data_recv[datetime.datetime.utcnow()] = data
		self.last_activity = datetime.datetime.utcnow()
		return data

	async def readuntil(self, separator=b'\n'):
		data = await self.reader.readuntil(separator=separator)
		if not data:
			return data
		self.traffic.data_recv[datetime.datetime.utcnow()] = data
		self.last_activity = datetime.datetime.utcnow()
		return data

	async def readline(self):
		data = await self.reader.readline()
		if not data:
			return data
		self.traffic.data_recv[datetime.datetime.utcnow()] = data
		self.last_activity = datetime.datetime.utcnow()
		return data

	def at_eof(self):
		return self.reader.at_eof()

	async def switch_ssl(self, new_transport):
		"""
		"""
		self.reader._transport = new_transport
		self.reader._over_ssl = True
		self.traffic.data_recv[datetime.datetime.utcnow()] = b'<SSL SWITCH>'


class StreamWriterLogging:
	def __init__(self, writer):
		self.writer = writer
		self.traffic = TrafficLog()
	
	@property
	def peer_address(self):
		addr = self.writer.get_extra_info('peer_address')
		if addr is None:
			addr = ('0.0.0.0',0)
		return addr

	async def log_comms(self):
		return self.traffic

	def write(self, data):
		self.traffic.data_sent[datetime.datetime.utcnow()] = data
		self.writer.write(data)
		
	def write_broadcast(self, data, addr):
		self.traffic.data_sent[datetime.datetime.utcnow()] = b'<BROADCAST>'
		self.writer.write(data, addr)
		self.traffic.data_sent[datetime.datetime.utcnow()] = data

	def writelines(self, data):
		self.traffic.data_sent[datetime.datetime.utcnow()] = data
		self.writer.writelines(data)

	def write_eof(self):
		return self.writer.write_eof()

	def can_write_eof(self):
		return self.writer.can_write_eof()

	def close(self):
		return self.writer.close()

	def is_closing(self):
		return self.writer.is_closing()

	async def wait_closed(self):
		await self.writer.wait_closed

	def get_extra_info(self, name, default=None):
		return self.writer.get_extra_info(name, default)

	async def drain(self):
		await self.writer.drain()

	def pause_reading(self):
		self.writer.transport.pause_reading()

	async def switch_ssl(self, ssl_ctx):
		loop = asyncio.get_event_loop()
		protocol = self.writer.transport.get_protocol()
		new_transport = await loop.start_tls(
			self.writer.transport, 
			protocol, 
			ssl_ctx, 
			server_side=True, 
			ssl_handshake_timeout=None
		)

		self.writer._transport = new_transport
		self.writer._protocol._transport = new_transport
		self.writer._over_ssl = True

		self.traffic.data_sent[datetime.datetime.utcnow()] = b'<SSL SWITCH>'

		return new_transport
