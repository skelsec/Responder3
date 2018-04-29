import abc
import asyncio
import logging
import io
import traceback
import copy
import sys

from responder3.core.commons import *


class ResponderServerLogger:
	def __init__(self, log_queue, server_name, loop=None):
		self.log_queue = log_queue
		self.server_name = server_name
		self.loop = loop if loop is not None else asyncio.get_event_loop()

	async def aio_log(self, logentry):
		await self.log_queue.put(logentry)

	def log(self, message, level=logging.INFO):
		"""
		Create a log message and send it to the LogProcessor for processing
		"""
		self.loop.create_task(self.aio_log(LogEntry(level, self.server_name, message)))


class ResponderServerGlobalSession(ResponderServerLogger):
	def __init__(self, log_queue, server_name):
		ResponderServerLogger.__init__(self, log_queue, server_name)


class ResponderServerSession(abc.ABC, ResponderServerLogger):
	def __init__(self, connection, log_queue, server_name):
		ResponderServerLogger.__init__(self, log_queue, server_name)
		self.connection = connection


class ResponderServer(abc.ABC):
	def __init__(self, connection, session, server, globalsession=None, loop=None):
		try:
			self.loop = loop
			if self.loop is None:
				self.loop = asyncio.get_event_loop()
			self.session = session
			self.caddr = self.session.connection.get_remote_address()
			self.creader = connection[0]
			self.cwriter = connection[1]
			self.logQ    = server.log_queue
			self.rdns    = server.reverse_domain_table
			self.listener_socket_config = server.listener_socket_config
			self.listener_socket_ssl_context = server.listener_socket_ssl_context
			self.server_name = server.server_name
			self.settings= copy.deepcopy(server.server_handler_settings)
			self.globalsession = globalsession

			self.init()
		except Exception as e:
			print(e)

	@abc.abstractmethod
	def init(self):
		pass

	def slog(self, message, level=logging.INFO):
		self.loop.create_task(self.log(LogEntry(level, 'aaaa', message)))

	async def log(self, message, level=logging.INFO):
		"""
		Create a log message and send it to the LogProcessor for processing
		"""
		message = '[%s] <-> [%s] %s' % (
			self.listener_socket_config.get_print_address(),
			self.session.connection.get_remote_print_address(),
			message
		)
		await self.logQ.put(LogEntry(level, self.server_name, message))

	async def log_credential(self, credential):
		"""
		Create a Result message and send it to the LogProcessor for procsesing
		"""
		print(credential)
		credential.module = self.server_name
		credential.client_addr = self.session.connection.remote_ip
		credential.client_rdns = self.session.connection.remote_ip
		await self.logQ.put(credential)

	async def log_poisonresult(self, requestName = None, poisonName = None, poisonIP = None):
		await self.log('Resolv request in!')
		pr = PoisonResult()
		pr.module = self.server_name
		pr.target = self.session.connection.remote_ip
		pr.request_name = requestName
		pr.request_type = None
		pr.poison_name = poisonName
		pr.poison_addr = poisonIP
		pr.mode = self.settings['mode']

		await self.logQ.put(pr)

	async def log_email(self, emailEntry):
		await self.log('You got mail!', logging.INFO)
		await self.logQ.put(emailEntry)

	async def log_proxy(self, data, laddr, raddr, level = logging.INFO):
		message = '[%s -> %s] %s' % ('%s:%d' % laddr, '%s:%d' % raddr, data)
		await self.logQ.put(LogEntry(level, self.server_name, message))

	async def log_proxydata(self, data, laddr, raddr, isSSL, datatype):
		pd = ProxyData()
		pd.src_addr  = laddr
		pd.dst_addr  = raddr
		pd.proto     = self.listener_socket_config.bind_protocol
		pd.isSSL     = isSSL
		pd.data_type = datatype
		pd.data      = data

		await self.logQ.put(pd)

	async def log_data(self, cmd):
		await self.logQ.put(cmd)

	async def log_exception(self, message=None):
		sio = io.StringIO()
		ei = sys.exc_info()
		tb = ei[2]
		traceback.print_exception(ei[0], ei[1], tb, None, sio)
		msg = sio.getvalue()
		if msg[-1] == '\n':
			msg = msg[:-1]
		sio.close()
		if message is not None:
			msg = message + msg
		await self.log(msg, level=logging.ERROR)
