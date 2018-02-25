import asyncio
import socket
import io
import ipaddress

def recvfrom(loop, sock, n_bytes, fut=None, registed=False):
	fd = sock.fileno()
	if fut is None:
		fut = loop.create_future()
	if registed:
		loop.remove_reader(fd)

	try:
		data, addr = sock.recvfrom(n_bytes)
	except (BlockingIOError, InterruptedError):
		loop.add_reader(fd, recvfrom, loop, sock, n_bytes, fut, True)
	else:
		fut.set_result((data, addr))
	return fut

def sendto(loop, sock, data, addr, fut=None, registed=False):
	fd = sock.fileno()
	if fut is None:
		fut = loop.create_future()
	if registed:
		loop.remove_writer(fd)
	if not data:
		return

	try:
		n = sock.sendto(data, addr)	
	except (BlockingIOError, InterruptedError):
		loop.add_writer(fd, sendto, loop, sock, data, addr, fut, True)
	else:
		fut.set_result(n)
	return fut


class UDPReader():
	def __init__(self, data, addr):
		self._ldata = len(data)
		self._remaining = len(data)
		self._addr = addr
		self.buff = io.BytesIO(data)

	@asyncio.coroutine
	def read(self, n = -1):
		if n == -1:
			self._remaining = 0
		else:
			self._remaining -= n
		
		return self.buff.read(n)

	@asyncio.coroutine
	def readexactly(self, n):
		if n == -1:
			self._remaining = 0
		else:
			self._remaining -= n
		return self.buff.read(n)

	def at_eof(self):
		return self._remaining == 0



class UDPWriter():
	def __init__(self, loop, sock, addr, laddr):
		self._laddr = laddr
		self._addr = addr
		self._loop = loop
		self._sock = sock

	@asyncio.coroutine
	def drain(self):
		return

	@asyncio.coroutine
	def write(self, data, addr = None):
		if addr is None:
			yield from sendto(self._loop, self._sock, data, self._addr)
		else:
			yield from sendto(self._loop, self._sock, data, addr)

class UDPClient():
	def __init__(self, raddr, loop = None, sock = None):
		self._raddr  = raddr
		self._socket = sock
		self._loop   = loop
		self._laddr  = None
		if loop is None:
			self._loop = asyncio.get_event_loop()

	def start_socket(self):
		family = socket.AF_INET if ipaddress.ip_address(self._raddr[0]).version == 4 else socket.AF_INET6
		self._socket = socket.socket(family, socket.SOCK_DGRAM, 0)
		self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self._socket.setblocking(False)
		self._socket.bind(('', 0))
		self._laddr  = self._socket.getsockname()

	@asyncio.coroutine
	def run(self, data):
		if self._socket is None:
			self.start_socket()
		writer = UDPWriter(self._loop, self._socket, self._raddr, self._laddr)
		yield from writer.write(data)
		data, addr = yield from recvfrom(self._loop, self._socket, 65536)
		reader = UDPReader(data, addr)
		return (reader,writer)

#https://www.pythonsheets.com/notes/python-asyncio.html
class UDPServer():
	def __init__(self, callback, socketKwargs, loop = None, socket = None):
		self._callback = callback
		self._socketKwargs = socketKwargs
		self._socket = socket
		self._loop   = loop
		if self._socketKwargs is None:
			if self._socket is None:
				raise Exception('Either socket or socketKwargs MUST be defined!')
			self._laddr  = self._socket.getsockname()
		else:
			self._laddr  = (self._socketKwargs['host'], self._socketKwargs['port'])
		if loop is None:
			self._loop = asyncio.get_event_loop()

	def start_socket(self):
		self._socket = socket.socket(self._socketKwargs['family'], socket.SOCK_DGRAM, 0)
		if self._socketKwargs['reuse_address']:
			self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self._socket.setblocking(False)
		try:
			self._socket.bind((self._socketKwargs['host'], self._socketKwargs['port']))
		except Exception as e:
			print(self._socketKwargs['host'])
			print(self._socketKwargs['port'])
			raise(e)


	@asyncio.coroutine
	def run(self):
		if self._socket is None:
			self.start_socket()
		while True:
			data, addr = yield from recvfrom(self._loop, self._socket, 65536)
			reader = UDPReader(data, addr)
			writer = UDPWriter(self._loop, self._socket, addr, self._laddr)
			self._callback(reader, writer)