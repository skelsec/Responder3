import sys
import socket
import copy
import importlib
import importlib.util
import asyncio
import datetime

from responder3.core.ssl import SSLContextBuilder
from responder3.core.commons import *
from responder3.core.logging.logtask import *
from responder3.core.logging.logger import *


from responder3.core.sockets import setup_base_socket

from responder3.core.streams.logging_streams import *

class ConnectionTask:
	def __init__(self, connection):
		self.connection = connection
		self.handler    = None
		self.created_at = datetime.datetime.utcnow()
		self.started_at = None

class ConnectionWhatchDog:
	"""
	Terminates the connection in case there wasnt any activity on it after a given period of time
	"""
	def __init__(self, task, reader, logger, connection_closing_evt, timeout = 10):
		self.target_task = task
		self.creader = reader
		self.timeout = timeout
		self.logger = logger
		self.connection_closing_evt = connection_closing_evt

	@r3exception
	async def run(self):
		while not self.connection_closing_evt.is_set():
			last_activity = (datetime.datetime.utcnow() - self.creader.last_activity).total_seconds()
			if last_activity > self.timeout:
				print('cancelling task!')
				self.target_task.cancel()
				break
				#raise Exception('Client connection timeout')
			await asyncio.sleep(self.timeout)

class Responder3ServerTask:
	def __init__(self, log_queue = None, reverse_domain_table=None, server_command_queue=None, loop=None, rdns_resolver = None):
		self.logger = Logger('Responder3ServerTask', logQ = log_queue)
		self.shutdown_evt = asyncio.Event()
		self.loop = loop if loop is not None else asyncio.get_event_loop()
		self.log_queue = log_queue if log_queue is not None else asyncio.Queue()
		self.reverse_domain_table = reverse_domain_table if reverse_domain_table is not None else {}
		self.server_command_queue = server_command_queue
		self.server_name = None
		self.server_config = None
		self.listener_socket_config = None
		self.listener_socket_ssl_context = None
		self.server_handler = None
		self.server_handler_settings = None
		self.server_handler_session = None
		self.server_handler_global_session = None
		self.connections = {}
		self.rdns_resolver = rdns_resolver
		self.connection_factory = ConnectionFactory(self.reverse_domain_table, self.rdns_resolver)

	@r3exception
	async def accept_client(self, client_reader, client_writer):
		"""
		Handles incoming connection.
		1. Creates connection obj
		2. Log connection
		3. Schedules a new task with the appropriate server template's run method
		4. Performs cleanup after connection terminates
		:param client_reader:
		:type client_reader: asyncio.StreamReader
		:param client_writer:
		:type client_writer: asyncio.StreamWriter
		:return: None
		"""
		client_reader = StreamReaderLogging(client_reader)
		client_writer = StreamWriterLogging(client_writer)
		connection = await self.connection_factory.from_streamwriter(client_writer)
		shutdown_evt = asyncio.Event()
		await self.logger.connection(connection, ConnectionStatus.OPENED)
		ct = ConnectionTask(connection)
		
		#setting up server temaplte
		ct.handler = self.server_handler(
			self.server_name,
			self.server_handler_settings,
			client_reader,
			client_writer,
			self.server_handler_session(connection, self.log_queue),
			self.log_queue,
			self.listener_socket_config,
			self.listener_socket_ssl_context,
			shutdown_evt,
			rdns_resolver = self.rdns_resolver,
			globalsession = self.server_handler_global_session,
			loop = self.loop
		)
		ct.started_at = datetime.datetime.utcnow()
		await self.logger.debug('Starting server task!')
		self.connections[ct] = 1

		#starting server template
		template_run_task = asyncio.create_task(ct.handler.run())

		#starting whatchdog
		whatchdog = ConnectionWhatchDog(template_run_task, client_reader, Logger('%s[WHATCHDOG]' % self.server_name, logQ = self.log_queue), ct.handler.shutdown_evt, timeout = 10)
		whatchdog_task = asyncio.create_task(whatchdog.run())

		#waiting template to finish
		await template_run_task

		ct.handler.shutdown_evt.set()
		await self.logger.connection(ct.connection, ConnectionStatus.CLOSED)

		try:
			ct.connection.writer.close()
		except Exception as e:
			#if we cannot close the socket then be it
			pass

		del self.connections[ct]
		return

	@staticmethod
	def import_template(template_name):
		"""
		Imports necessary modules for the specific type of server.
		This way we avoid importing all available modules before forking.
		:return: None
		"""
		handler_spec = importlib.util.find_spec('responder3.poisoners.%s' % template_name)
		if handler_spec is None:
			handler_spec = importlib.util.find_spec('responder3.servers.%s' % template_name)
			if handler_spec is None:
				raise Exception('Could not find the package for %s' % (template_name,))
			else:
				servermodule = importlib.import_module('responder3.servers.%s' % template_name)
		else:
			servermodule = importlib.import_module('responder3.poisoners.%s' % template_name)

		return servermodule

	@r3exception
	async def create_server(self, server_task_config):
		self.server_config = server_task_config

		if 'listener_socket_config' in server_task_config and server_task_config['listener_socket_config'] is not None:
			self.listener_socket_config = server_task_config['listener_socket_config']
		else:
			raise Exception('Server listener socket MUST be defined!')

		if 'settings' in server_task_config:
			self.server_handler_settings = copy.deepcopy(server_task_config['settings'])

		if 'handler' in server_task_config and server_task_config['handler'] is not None:
			server_module = Responder3ServerTask.import_template(
				server_task_config['handler'],
			)
			self.server_handler = getattr(server_module, server_task_config['handler'])
			self.server_handler_session = getattr(server_module, '%s%s' % (server_task_config['handler'], 'Session'))
			# global session object will be immediately instantiated, as it is global for ALL clients
			gs = getattr(server_module, '%s%s' % (server_task_config['handler'], 'GlobalSession'), None)
			if gs is not None:
				self.server_handler_global_session = gs(self.listener_socket_config, self.server_handler_settings, self.log_queue)
		else:
			raise Exception('Server Handler MUST be specified!')

		if 'bind_sslctx' in server_task_config:
			self.listener_socket_config.is_ssl_wrapped = True
			self.listener_socket_ssl_context = SSLContextBuilder.from_dict(server_task_config['bind_sslctx'], server_side=True)

		
		if self.listener_socket_ssl_context is not None:
			self.server_name = '%s-%s' % (self.server_handler.__name__, 'SSL')
		else:
			self.server_name = '%s-%s' % (self.server_handler.__name__, self.listener_socket_config.get_protocolname())

		#replacing logger with a new one that has the name now
		self.logger = Logger(self.server_name, logQ = self.log_queue)

		self.server_coro = None

		if self.listener_socket_config.bind_protocol == socket.SOCK_STREAM:
			sock = None
			if getattr(self.server_handler, "custom_socket", None) is not None and callable(
					getattr(self.server_handler, "custom_socket", None)):
				sock = self.server_handler.custom_socket(self.listener_socket_config)
			else:
				sock = setup_base_socket(self.listener_socket_config)

			self.server_coro = await asyncio.start_server(self.accept_client, sock=sock, ssl=self.listener_socket_ssl_context)

		elif self.listener_socket_config.bind_protocol == socket.SOCK_DGRAM:
			udpserver_obj = getattr(importlib.import_module('responder3.core.udpwrapper'), 'UDPServer')
			sock = None
			if getattr(self.server_handler, "custom_socket", None) is not None and callable(
					getattr(self.server_handler, "custom_socket", None)):
				sock = self.server_handler.custom_socket(self.listener_socket_config)

			udpserver = udpserver_obj(self.accept_client, self.listener_socket_config, sock=sock)
			#self.server_coro = udpserver.run()
			self.server_coro = udpserver

		else:
			raise Exception('Unknown protocol type!')

		return self.server_coro
