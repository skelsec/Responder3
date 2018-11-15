import abc
import asyncio
import copy

from responder3.core.commons import *
from responder3.core.logging.logger import *


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
		self.rdns_resolver = rdns_resolver
		self.listener_socket_config = socket_config
		self.listener_socket_ssl_context = ssl_context
		self.settings = settings
		self.globalsession = globalsession
		self.shutdown_evt = shutdown_evt
		
		self.init()

	@abc.abstractmethod
	def init(self):
		pass

	@abc.abstractmethod
	async def run(self):
		pass
