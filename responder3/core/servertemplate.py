import abc
import asyncio
import logging
import io
import traceback
import copy
import sys

from responder3.core.commons import *


class ResponderServerSession(abc.ABC):
	def __init__(self, connection):
		self.connection = connection


class ResponderServer(abc.ABC):
	def __init__(self, connection, session, server_properties, globalsession=None, loop=None):
		self.loop = loop
		if self.loop is None:
			self.loop = asyncio.get_event_loop()
		self.session = session
		self.caddr   = self.session.connection.get_remote_address()
		self.creader = connection[0]
		self.cwriter = connection[1]
		self.logQ    = server_properties.shared_logQ
		self.rdns    = server_properties.shared_rdns
		self.server_properties  = server_properties
		self.settings= copy.deepcopy(server_properties.settings)
		self.globalsession = globalsession

		self.init()

	@abc.abstractmethod
	def init(self):
		pass

	def log(self, message, level=logging.INFO):
		"""
		Create a log message and send it to the LogProcessor for processing
		"""
		# if session is None or self.session.connection.remote_ip == None:
		# 	message = '[INIT] %s' %  message
		# else:
		# 	message = '[%s:%d] %s' % (self.session.connection.remote_ip, self.session.connection.remote_port, message)
		message = '[%s] <-> [%s] %s' % (self.server_properties.listener_socket_config.get_print_address(),
										self.session.connection.get_remote_print_address(),
										message)
		self.logQ.put(LogEntry(level, self.server_properties.module_name, message))

	def log_credential(self, credential):
		"""
		Create a Result message and send it to the LogProcessor for procsesing
		"""
		credential.module = self.server_properties.module_name
		credential.client_addr = self.session.connection.remote_ip
		credential.client_rdns = self.session.connection.remote_ip
		self.logQ.put(credential)

	def log_poisonresult(self, requestName = None, poisonName = None, poisonIP = None):
		self.log('Resolv request in!')
		pr = PoisonResult()
		pr.module = self.server_properties.module_name
		pr.target = self.session.connection.remote_ip
		pr.request_name = requestName
		pr.request_type = None
		pr.poison_name = poisonName
		pr.poison_addr = poisonIP
		pr.mode = self.settings['mode']

		self.logQ.put(pr)

	def log_email(self, emailEntry):
		self.log('You got mail!', logging.INFO)
		self.logQ.put(emailEntry)

	def log_proxy(self, data, laddr, raddr, level = logging.INFO):
		message = '[%s -> %s] %s' % ('%s:%d' % laddr, '%s:%d' % raddr, data)
		self.logQ.put(LogEntry(level, self.server_properties.module_name, message))

	def log_proxydata(self, data, laddr, raddr, isSSL, datatype):
		pd = ProxyData()
		pd.src_addr  = laddr
		pd.dst_addr  = raddr
		pd.proto     = self.server_properties.listener_socket_config.bind_protocol
		pd.isSSL     = isSSL
		pd.data_type = datatype
		pd.data      = data

		self.logQ.put(pd)

	def log_exception(self, message = None):
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
