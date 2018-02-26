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

from responder3.core import commons

sslcontexttable = {
	#'SSLv2' : ssl.PROTOCOL_SSLv2,
	#'SSLv3' : ssl.PROTOCOL_SSLv3,
	'SSLv23': ssl.PROTOCOL_SSLv23,
	'TLS' : ssl.PROTOCOL_TLS,
	'TLSv1' : ssl.PROTOCOL_TLSv1,
	'TLSv11' : ssl.PROTOCOL_TLSv1_1,
	'TLSv12' : ssl.PROTOCOL_TLSv1_2,
}

#TODO: enable additional fine-tuning of the SSL context from config file
class ServerProperties():
	"""
	this class takes the settings dictionary, parses it an constructs all variables that are needed to:
	1. set up server listener socket (including ssl context)
	2. holds the server and session objects that will be instantiated when the server process starts
	
	input: session dictionary

	settings dict MUST have a port the port, serverhandler, serversession parameters!!!
	"""
	def __init__(self):
		self.bind_addr     = None
		self.bind_port     = None
		self.bind_family   = None
		self.bind_porotcol = None
		self.bind_iface    = None
		self.bind_iface_idx = None
		self.serverhandler = None
		self.serversession = None
		self.serverglobalsession = None
		self.settings      = None
		self.sslcontext    = None
		self.shared_rdns   = None
		self.shared_logQ   = None
		self.interfaced    = None
		self.platform      = None

		self.platform = commons.get_platform()

	def from_dict(settings):

		sp = ServerProperties()

		if 'interfaced' in settings and settings['interfaced'] is not None:
			sp.interfaced = settings['interfaced']

		if 'bind_addr' in settings and settings['bind_addr'] is not None:
			sp.bind_addr = ipaddress.ip_address(settings['bind_addr'])

		sp.bind_family = socket.AF_INET if sp.bind_addr.version == 4 else socket.AF_INET6
		if 'bind_port' in settings and settings['bind_port'] is not None:
			sp.bind_port = int(settings['bind_port'])
			sp.bind_porotcol = commons.ServerProtocol[settings['bind_porotcol'].upper()]
		else:
			raise Exception('Port MUST be specified!')

		if 'bind_iface' in settings and settings['bind_iface'] is not None:
			sp.bind_iface = settings['bind_iface']
		else:
			raise Exception('interface name  MUST be provided!')

		if 'bind_iface_idx' in settings and settings['bind_iface_idx'] is not None:
			sp.bind_iface_idx = settings['bind_iface_idx']
		elif sp.bind_family == socket.AF_INET6:
			raise Exception('bind_iface_idx name  MUST be provided for IPv6 addresses!')

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
			sp.settings  = copy.deepcopy(settings['settings'])     #making a deepcopy of the server-settings part of the settings dict

		if 'sslsettings' in settings:
			sp.bind_porotcol = commons.ServerProtocol.SSL
			sslprotocol = ssl.PROTOCOL_TLSv1_2
			

			if 'protocol' in settings['sslsettings']:
				sslprotocol = sslcontexttable[settings['sslsettings']['protocol']]

			self.sslcontext = ssl.SSLContext(sslprotocol)
			self.sslcontext.load_cert_chain(certfile=settings['sslsettings']['certfile'], keyfile=settings['sslsettings']['keyfile'])
			
			#ssl_context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION)
			#ssl_context.set_ciphers(self.server.settings['SSL']['ciphers'])
			
			#ssl_context.set_alpn_protocols(['http/1.1'])

		if 'shared_rdns' in settings and settings['shared_rdns'] is not None:
			sp.shared_rdns = settings['shared_rdns']

		else:
			raise Exception('shared_rdns MUST be specified!')

		if 'shared_logQ' in settings and settings['shared_logQ'] is not None:
			sp.shared_logQ = settings['shared_logQ']

		else:
			raise Exception('shared_logQ MUST be specified!')

		return sp

	def getserverkwargs(self):
		"""
		returns an kwargs dict that is ready to be used by asyncio.start_server
		"""
		return {
			'host'   : str(self.bind_addr),
			'port'   : self.bind_port,
			'family' : self.bind_family,
			'ssl'    : self.sslcontext,
			'reuse_address' : True,
			'reuse_port'    : True,
			}


class ResponderServerProcess(multiprocessing.Process):
	"""
	The main server process for each server. Handles the incoming clients, maintains a table of active connections
	Takes a ServerProperties class as input for init
	"""
	def __init__(self, serverentry):
		multiprocessing.Process.__init__(self)
		self.serverentry = serverentry
		self.udpserver   = None
		self.sprops      = None
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

	def import_packages(self):
		if self.serverentry['bind_porotcol'].upper() == 'UDP':
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
		


	def accept_client(self,client_reader, client_writer):
		connection = self.connectionFactory.from_streamwriter(client_writer, self.sprops.bind_porotcol)		
		self.logConnection(connection, commons.ConnectionStatus.OPENED)
		server = self.server((client_reader, client_writer), self.session(connection), self.sprops, self.globalsession)
		self.log('Starting server task!', logging.DEBUG)
		task = asyncio.Task(server.run())
		#task = asyncio.ensure_future(server.run())
		self.clients[task] = (client_reader, client_writer)

		def client_done(task):
			del self.clients[task]
			if self.sprops.bind_porotcol == commons.ServerProtocol.TCP:
				client_writer.close()
			else:
				self.log('UDP task cleanup not implemented!', logging.DEBUG)
				pass
				
			self.logConnection(connection, commons.ConnectionStatus.CLOSED)
		task.add_done_callback(client_done)
		

	def setup(self):
		self.import_packages()
		self.sprops = ServerProperties.from_dict(self.serverentry)
		self.loop    = asyncio.get_event_loop()
		self.clients = {}
		self.server  = self.sprops.serverhandler
		self.session = self.sprops.serversession
		self.globalsession = self.sprops.serverglobalsession
		if self.sprops.serverglobalsession is not None:
			self.globalsession = self.sprops.serverglobalsession(self.sprops)
		self.logQ    = self.sprops.shared_logQ
		self.rdnsd   = self.sprops.shared_rdns
		self.connectionFactory = commons.ConnectionFactory(self.rdnsd)
		self.modulename = '%s-%s-%d' % (self.sprops.serverhandler.__name__, self.sprops.bind_addr, self.sprops.bind_port)
		self.serverCoro = None

		if self.sprops.bind_porotcol in [commons.ServerProtocol.TCP, commons.ServerProtocol.SSL]:
			self.serverCoro = asyncio.start_server(self.accept_client, **self.sprops.getserverkwargs())
		
		elif self.sprops.bind_porotcol == commons.ServerProtocol.UDP:
			soc = None
			if getattr(self.sprops.serverhandler, "custom_socket", None) is not None and callable(getattr(self.sprops.serverhandler, "custom_socket", None)):
				soc = self.sprops.serverhandler.custom_socket(self.sprops)
			udpserver = self.udpserver(self.accept_client, self.sprops.getserverkwargs(), socket = soc)
			self.serverCoro = udpserver.run()

		else:
			raise Exception('Unknown protocol type!')


	def run(self):
		self.setup()
		try:
			self.log('Server started!')
			self.loop.run_until_complete(self.serverCoro)
			#self.loop.run_forever()
		except KeyboardInterrupt:
			sys.exit(0)
		except Exception as e:
			traceback.print_exc()
			self.log('Main loop exception!', logging.ERROR)

	def from_dict(serverentry):
		rsp = ResponderServerProcess(serverentry)
		return rsp


	def log(self, message, level = logging.INFO):
		self.logQ.put(commons.LogEntry(level, self.modulename, message))

	def logConnection(self, connection, status):
		"""
		Create a Connection message and send it to the LogProcessor for procsesing
		connection: A connection object that holds the connection info for the client
		status : The connection status (ConnectionStatus enum)
		"""
		if status == commons.ConnectionStatus.OPENED or status == commons.ConnectionStatus.STATELESS:
			self.log('New connection opened from %s:%d' % (connection.remote_ip, connection.remote_port))
		elif status == commons.ConnectionStatus.CLOSED:
			self.log('Connection closed by %s:%d' % (connection.remote_ip, connection.remote_port))