import sys
import abc
import socket
import multiprocessing
import ipaddress
import copy
import io
import logging
import importlib
import importlib.util
import asyncio
import traceback
import ssl
import platform

from responder3.core.asyncio_helpers import wait_mp_event
from responder3.core.ssl import SSLContextBuilder
from responder3.core.commons import LogEntry, ConnectionStatus, ConnectionFactory, get_platform
from responder3.core.sockets import setup_base_socket


# TODO: enable additional fine-tuning of the SSL context from config file
class ServerProperties:
	def __init__(self):
		"""
		Describes all properties of a server.
		Used to set up server processes.
		"""
		self.listener_socket_config = None
		self.serverhandler = None
		self.serversession = None
		self.serverglobalsession = None
		self.settings      = None
		self.sslcontext    = None
		self.shared_rdns   = None
		self.shared_logQ   = None
		self.interfaced    = None
		self.platform      = get_platform()
		self.module_name   = None

	@staticmethod
	def from_dict(settings):
		"""
		Creates the ServerSettings object from a config dict
		:param settings: Dictionary describing the object
		:type settings: dict
		:return: ServerProperties
		"""
		sp = ServerProperties()

		if 'listener_socket_config' in settings and settings['listener_socket_config'] is not None:
			sp.listener_socket_config = settings['listener_socket_config']
		else:
			raise Exception('Server listener socket MUST be defined!')

		if 'serverhandler' in settings and settings['serverhandler'] is not None:
			sp.serverhandler = settings['serverhandler']

		else:
			raise Exception('Server Handler MUST be specified!')

		if 'serversession' in settings and settings['serversession'] is not None:
			sp.serversession = settings['serversession']

		else:
			raise Exception('Server Session MUST be specified!')

		if 'globalsession' in settings and settings['globalsession'] is not None:
			sp.serverglobalsession = settings['globalsession']

		if 'settings' in settings:
			sp.settings  = copy.deepcopy(settings['settings'])     # making a deepcopy of the server-settings part of the settings dict

		if 'bind_sslctx' in settings:
			sp.listener_socket_config.is_ssl_wrapped = True
			sslctx = settings['bind_sslctx'] if isinstance(settings['bind_sslctx'], dict) else settings['bind_sslctx'][0] # sometimes deepcpy creates a touple insted of dict here
			sp.sslcontext = SSLContextBuilder.from_dict(settings['bind_sslctx'], server_side= True)

		if 'shared_rdns' in settings and settings['shared_rdns'] is not None:
			sp.shared_rdns = settings['shared_rdns']

		else:
			raise Exception('shared_rdns MUST be specified!')

		if 'shared_logQ' in settings and settings['shared_logQ'] is not None:
			sp.shared_logQ = settings['shared_logQ']

		else:
			raise Exception('shared_logQ MUST be specified!')

		sp.module_name = '%s-%s' % (sp.serverhandler.__name__, sp.listener_socket_config.get_protocolname())
		if sp.sslcontext is not None:
			sp.module_name += '-SSL'

		return sp

	def getserverkwargs(self):
		"""
		Creates a dict that is to be used by asyncio.start_server
		:return: dict
		"""
		socket_kwargs = self.listener_socket_config.get_server_kwargs()
		socket_kwargs['ssl'] = self.sslcontext
		return socket_kwargs

	def __repr__(self):
		t  = '== ServerProperties ==\r\n'
		t += 'listenersocket : %s \r\n' % repr(self.listener_socket_config)
		t += 'serverhandler : %s \r\n' % repr(self.serverhandler)
		t += 'serversession : %s \r\n' % repr(self.serversession)
		t += 'serverglobalsession : %s \r\n' % repr(self.serverglobalsession)
		t += 'settings : %s \r\n' % repr(self.settings)
		t += 'sslcontext : %s \r\n' % repr(self.sslcontext)
		t += 'shared_rdns : %s \r\n' % repr(self.shared_rdns)
		t += 'shared_logQ : %s \r\n' % repr(self.shared_logQ)
		return t


class ResponderServerProcess(multiprocessing.Process):
	def __init__(self, serverentry):
		"""
		The main server process for each server. Handles the incoming clients, maintains a table of active connections

		:param serverentry: Dictionary describing the server process
		:type serverentry: dict
		"""
		multiprocessing.Process.__init__(self)
		self.serverentry = serverentry
		self.udpserver   = None
		self.server_properties      = None
		self.loop        = None
		self.clients     = None
		self.server      = None
		self.session     = None
		self.logQ        = None
		self.rdnsd       = None
		self.modulename  = None
		self.serverCoro  = None
		self.globalsession = None
		self.connectionFactory = None
		self.server_stop_event = None

	def import_packages(self):
		"""
		Imports necessary modules for the specific type of server.
		This way we avoid importing all available modules before forking.
		:return: None
		"""
		# print(self.serverentry['listener_socket_config'])
		if self.serverentry['listener_socket_config'].bind_protocol == socket.SOCK_DGRAM:
			self.udpserver = getattr(importlib.import_module('responder3.core.udpwrapper'), 'UDPServer')
		
		handler_spec = importlib.util.find_spec('responder3.poisoners.%s' % self.serverentry['handler'])
		if handler_spec is None:
			handler_spec = importlib.util.find_spec('responder3.servers.%s' % self.serverentry['handler'])
			if handler_spec is None:
				raise Exception('Could not find the package for %s' % (self.serverentry['handler'],))
			else:
				servermodule = importlib.import_module('responder3.servers.%s' % self.serverentry['handler'])
		else:
			servermodule = importlib.import_module('responder3.poisoners.%s' % self.serverentry['handler'])

		self.serverentry['serverhandler'] = getattr(servermodule, self.serverentry['handler'])
		self.serverentry['serversession'] = getattr(servermodule, '%s%s' % (self.serverentry['handler'], 'Session'))
		self.serverentry['globalsession'] = getattr(servermodule, '%s%s' % (self.serverentry['handler'], 'GlobalSession'), None)

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
		connection = self.connectionFactory.from_streamwriter(client_writer)
		self.log_connection(connection, ConnectionStatus.OPENED)
		server = self.server((client_reader, client_writer), self.session(connection), self.server_properties, self.globalsession)
		self.log('Starting server task!', logging.DEBUG)
		task = asyncio.Task(server.run())
		self.clients[task] = (client_reader, client_writer)

		def client_done(task):
			del self.clients[task]
			client_writer.close()
				
			self.log_connection(connection, ConnectionStatus.CLOSED)
		task.add_done_callback(client_done)

	def setup(self):
		"""
		Upsets the server. :)
		Imports necessary modules, parses configuration dict, creates session obj...
		:return: None
		"""
		self.import_packages()
		self.server_properties = ServerProperties.from_dict(self.serverentry)
		self.loop    = asyncio.get_event_loop()
		self.clients = {}
		self.server  = self.server_properties.serverhandler
		self.session = self.server_properties.serversession
		self.globalsession = self.server_properties.serverglobalsession
		if self.server_properties.serverglobalsession is not None:
			self.globalsession = self.server_properties.serverglobalsession(self.server_properties)
		self.logQ    = self.server_properties.shared_logQ
		self.rdnsd   = self.server_properties.shared_rdns
		self.connectionFactory = ConnectionFactory(self.rdnsd)
		self.modulename = '%s-%s' % (self.server_properties.serverhandler.__name__, str(self.server_properties.listener_socket_config.get_print_address()))
		self.serverCoro = None
		self.server_stop_event = asyncio.Event()

		if self.server_properties.listener_socket_config.bind_protocol == socket.SOCK_STREAM:
			sock = None
			if getattr(self.server_properties.serverhandler, "custom_socket", None) is not None and callable(getattr(self.server_properties.serverhandler, "custom_socket", None)):
				sock = self.server_properties.serverhandler.custom_socket(self.server_properties.listener_socket_config)
			else:
				sock = setup_base_socket(self.server_properties.listener_socket_config)
			
			self.serverCoro = asyncio.start_server(self.accept_client, sock = sock, ssl=self.server_properties.sslcontext)
		
		elif self.server_properties.listener_socket_config.bind_protocol == socket.SOCK_DGRAM:
			sock = None
			if getattr(self.server_properties.serverhandler, "custom_socket", None) is not None and callable(getattr(self.server_properties.serverhandler, "custom_socket", None)):
				sock = self.server_properties.serverhandler.custom_socket(self.server_properties.listener_socket_config)
			
			udpserver = self.udpserver(self.accept_client, self.server_properties, sock = sock)
			self.serverCoro = udpserver.run()

		else:
			raise Exception('Unknown protocol type!')

	def run(self):
		try:
			self.setup()
			self.log('Server started!')
			self.loop.run_until_complete(self.serverCoro)
			self.loop.run_forever()
		except KeyboardInterrupt:
			sys.exit(0)
		except Exception as e:
			self.log_exception('Server is closing because of error!')
			pass

	@staticmethod
	def from_dict(serverentry):
		"""
		Creates the server process with properties specified in serveerenty
		:param serverentry: Configuration object
		:type serverentry: dict
		:return: ResponderServerProcess
		"""
		rsp = ResponderServerProcess(serverentry)
		return rsp

	def log_exception(self, message = None):
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

	def log(self, message, level = logging.INFO):
		"""
		Sends the log messages onto the logqueue. If no logqueue is present then prints them out on console.
		:param message: The message to be sent
		:type message: str
		:param level: Log level
		:type level: int
		:return: None
		"""
		if self.logQ is not None:
			self.logQ.put(LogEntry(level, self.modulename, message))
		else:
			print(str(LogEntry(level, self.modulename, message)))

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
