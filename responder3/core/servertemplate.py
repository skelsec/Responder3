import abc
import asyncio
import copy

from responder3.core.commons import *
from responder3.core.logging.logger import *
from responder3.core.udpwrapper import *

class ResponderServerGlobalSession:
	def __init__(self, log_queue, server_name):
		self.logger = Logger(server_name, logQ = log_queue)


class ResponderServerSession(abc.ABC):
	def __init__(self, connection, log_queue, server_name):
		self.connection = connection
		self.logger = Logger(server_name, logQ = log_queue)

class ResponderServer(abc.ABC):
	def __init__(self, server_name, settings, reader, writer, session, log_queue, socket_config, ssl_context, shutdown_evt, rdns_resolver = None,globalsession=None, loop=None):
		self.loop = loop
		if self.loop is None:
			self.loop = asyncio.get_event_loop()

		self.session = session
		self.server_name = '%s[%s]' % (server_name, self.session.connection.get_remote_print_address())
		self.logger = Logger(server_name, logQ = log_queue, connection = self.session.connection)
		
		self.caddr = self.session.connection.get_remote_address()
		self.creader = reader
		self.cwriter = writer
		self.cproto = 'UDP' if isinstance(writer.writer, UDPWriter) else 'TCP'
		self.rdns_resolver = rdns_resolver
		self.listener_socket_config = socket_config
		self.listener_socket_ssl_context = ssl_context
		self.settings = settings
		self.globalsession = globalsession
		self.shutdown_evt = shutdown_evt
		
		self.init()

	def get_default_ssl_ctx(self):
		return get_default_ctx()

	async def switch_ssl(self, ssl_ctx):
		new_transport = await self.cwriter.switch_ssl(ssl_ctx)
		await self.creader.switch_ssl(new_transport)
		return

	@abc.abstractmethod
	def init(self):
		pass

	@abc.abstractmethod
	async def run(self):
		pass
