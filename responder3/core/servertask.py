import sys
import socket
import copy
import io
import logging
import importlib
import importlib.util
import asyncio
import traceback
import datetime

from responder3.core.ssl import SSLContextBuilder
from responder3.core.commons import LogEntry, ConnectionStatus, ConnectionFactory, get_platform
from responder3.core.sockets import setup_base_socket

class ConnectionTask:
	def __init__(self, connection):
		self.connection = connection
		self.handler_coro = None
		self.created_at = datetime.datetime.utcnow()
		self.started_at = None

class Responder3ServerTask:
	def __init__(self, log_queue = None, reverse_domain_table=None, server_command_queue=None, loop=None):
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
		self.connection_factory = ConnectionFactory(self.reverse_domain_table)
		self.udpserver = None

	def accept_client(self, client_reader, client_writer):
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
		try:
			connection = self.connection_factory.from_streamwriter(client_writer)
			self.log_connection(connection, ConnectionStatus.OPENED)
			ct = ConnectionTask(connection)
			ct.handler = self.server_handler(
				(client_reader, client_writer),
				self.server_handler_session(connection, self.log_queue),
				self,
				self.server_handler_global_session,
				self.loop
			)
			ct.handler.coro = ct.handler.run()
			task = self.loop.create_task(ct.handler.coro)
			ct.started_at = datetime.datetime.utcnow()

			self.log('Starting server task!', logging.DEBUG)
			self.connections[task] = ct

			def client_done(task):
				try:
					self.log_connection(ct.connection, ConnectionStatus.CLOSED)
					ct.connection.writer.close()
					del self.connections[task]
				except Exception as e:
					print(str(e))

			task.add_done_callback(client_done)
		except Exception:
			self.log_exception()

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

	def create_server_coro(self, server_task_config):
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

		self.server_name = '%s-%s' % (self.server_handler.__name__, self.listener_socket_config.get_protocolname())
		if self.listener_socket_ssl_context is not None:
			self.server_name += '-SSL'

		self.server_coro = None

		if self.listener_socket_config.bind_protocol == socket.SOCK_STREAM:
			sock = None
			if getattr(self.server_handler, "custom_socket", None) is not None and callable(
					getattr(self.server_handler, "custom_socket", None)):
				sock = self.server_handler.custom_socket(self.listener_socket_config)
			else:
				sock = setup_base_socket(self.listener_socket_config)

			self.server_coro = asyncio.start_server(self.accept_client, sock=sock, ssl=self.listener_socket_ssl_context)

		elif self.listener_socket_config.bind_protocol == socket.SOCK_DGRAM:
			udpserver_obj = getattr(importlib.import_module('responder3.core.udpwrapper'), 'UDPServer')
			sock = None
			if getattr(self.server_handler, "custom_socket", None) is not None and callable(
					getattr(self.server_handler, "custom_socket", None)):
				sock = self.server_handler.custom_socket(self.listener_socket_config)

			udpserver = udpserver_obj(self.accept_client, self.listener_socket_config, sock=sock)
			self.server_coro = udpserver.run()

		else:
			raise Exception('Unknown protocol type!')

		return self.server_coro

	def log_exception(self, message=None):
		"""
		Custom exception handler to log exceptions via the logging interface
		:param message: Extra message for the exception if any
		:type message: str
		:return: None
		"""
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
		self.log(msg, level=logging.ERROR)

	async def aio_log(self, logentry):
		await self.log_queue.put(logentry)

	def log(self, message, level=logging.INFO):
		"""
		Sends the log messages onto the logqueue. If no logqueue is present then prints them out on console.
		:param message: The message to be sent
		:type message: str
		:param level: Log level
		:type level: int
		:return: None
		"""

		if self.log_queue is not None:
			self.loop.create_task(self.aio_log(LogEntry(level, self.server_name, message)))
		else:
			print(str(LogEntry(level, self.server_name, message)))

	def log_connection(self, connection, status):
		"""
		Logs incoming connection
		:param connection: The Connection object to log
		:type connection: Connection
		:param status: Connection status
		:type: ConnectionStatus
		:return: None
		"""
		if status == ConnectionStatus.OPENED or status == ConnectionStatus.STATELESS:
			self.log('New connection opened from %s:%d' % (connection.remote_ip, connection.remote_port))
		elif status == ConnectionStatus.CLOSED:
			self.log('Connection closed by %s:%d' % (connection.remote_ip, connection.remote_port))
