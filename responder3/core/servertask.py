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
from responder3.core.commons import LogEntry, ConnectionStatus, ConnectionFactory, get_platform, ConnectionClosed, ConnectionOpened
from responder3.core.sockets import setup_base_socket
from responder3.core.logtask import *

class ConnectionTask:
	def __init__(self, connection):
		self.connection = connection
		self.handler_coro = None
		self.created_at = datetime.datetime.utcnow()
		self.started_at = None

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
		self.udpserver = None

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
		connection = await self.connection_factory.from_streamwriter(client_writer)
		await self.logger.log_connection(connection, ConnectionStatus.OPENED)
		ct = ConnectionTask(connection)
		ct.handler = self.server_handler(
			(client_reader, client_writer),
			self.server_handler_session(connection, self.log_queue),
			self,
			self.server_handler_global_session,
			self.loop
		)
		ct.started_at = datetime.datetime.utcnow()
		await self.logger.debug('Starting server task!')
		self.connections[ct] = 1

		await ct.handler.run()
		await self.logger.log_connection(ct.connection, ConnectionStatus.CLOSED)

		try:
			ct.connection.writer.close()
		except Exception as e:
			#if we cannot close the socket then be it
			pass

		del self.connections[ct]

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

		self.server_name = '%s-%s' % (self.server_handler.__name__, self.listener_socket_config.get_protocolname())
		if self.listener_socket_ssl_context is not None:
			self.server_name += '-SSL'

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
			self.server_coro = udpserver.run()

		else:
			raise Exception('Unknown protocol type!')

		return self.server_coro
