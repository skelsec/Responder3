import traceback
import logging
import io
import os
import re
import copy
import time
import asyncio
import socket
import threading
import collections
from responder3.utils import ServerFunctionality
from responder3.core.common import * 
from responder3.core.servertemplate import ResponderServer, ResponderProtocolTCP, ProtocolSession


class TCPProxySession(ProtocolSession):
	def __init__(self):
		ProtocolSession.__init__(self)
		self.clientTransport = None
		self.remote_writer = None
		self.remote_socket = None

@asyncio.coroutine
def remote_socket_reader(s, transport):
	while True:
		pass

"""
@asyncio.coroutine
def proxy_open_connection(dest_addr, dest_port, transport, session):
	try:
		fut = asyncio.open_connection(dest_addr, dest_port)
		session.remote_reader, session.remote_writer = yield from asyncio.wait_for(fut, timeout=3)
	except asyncio.TimeoutError:
		transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.HOST_UNREACHABLE, IPv4Address('0.0.0.0'), 0).to_bytes())
		transport.close()
		return
	except ConnectionRefusedError:
		transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.CONN_REFUSED, IPv4Address('0.0.0.0'), 0).to_bytes())
		transport.close()
		return
	except Exception as e:
		print(str(e))
		transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.FAILURE, IPv4Address('0.0.0.0'), 0).to_bytes())
		transport.close()
		return
"""



class TCPProxyClientProtocol(asyncio.Protocol):
	def __init__(self, proto):
		asyncio.Protocol.__init__(self)#serverTransport, rdns, logQ
		self.logQ = proto._server.logQ
		self.serverTransport = proto._transport
		self.transport = None
		self.connection = Connection(proto._session.connection.rdnsd)
	
	def modulename(self):
		return 'TCPProxyClient'

	def log(self, level, message):
		self.logQ.put(LogEntry(level, self.modulename(), '[%s:%d] %s' % (self.connection.remote_ip, self.connection.remote_port, message)))

	def logConnection(self):
		if self.connection.status == ConnectionStatus.OPENED:
			self.log(logging.INFO, 'New connection opened')

		elif self.connection.status == ConnectionStatus.CLOSED:
			self.log(logging.INFO, 'Connection closed')
		self.logQ.put(self.connection)

	def data_received(self, raw_data):
		self.serverTransport.write(raw_data)

	def connection_made(self, transport):
		self.connection.setupTCP(transport.get_extra_info('socket'), ConnectionStatus.OPENED)
		self.logConnection()
		self.transport = transport

	def connection_lost(self, exc):
		self.connection.status = ConnectionStatus.CLOSED
		self.logConnection()


@asyncio.coroutine
def create_clinet_connection(dest_addr, dest_port, protocol):
	print('3')
	protocol._session.clientTransport, clientProtocol = yield from protocol._server.loop.create_connection(
															lambda: TCPProxyClientProtocol(protocol), 
															host = dest_addr, 
															port = dest_port)
	print(protocol._session.clientTransport)



class TCPProxyProtocol(ResponderProtocolTCP):
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)
		self._buffer_maxsize = 1024*1024
		self._session = copy.deepcopy(server.protocolSession)

	def _connection_made(self):
		#here do a lookup and decide where to proxy the connection
		dest_addr, dest_port = ('444.hu', 80)
		#
		print('1')
		task = self._server.loop.create_task(create_clinet_connection(dest_addr, dest_port, self))
		asyncio.wait([task])
		print('2')

		#loop.create_task(remote_socket_reader(self.remote_socket, self.transport))

	def _parsebuff(self):
		self._session.clientTransport.write(self._buffer)
		#self._session.remote_socket.sendall(self._buffer)

class TCPProxy(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		### BE CAREFUL, THE proxyTable IS NOT PART OF THE SESSION OBJECT!
		self.proxyTable = {}

	def setup(self):
		self.protocol = TCPProxyProtocol
		self.protocolSession = TCPProxySession()


	def modulename(self):
		return 'TCPProxy'

	def handle(self, packet, transport, session):
		pass