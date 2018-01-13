from abc import ABC, abstractmethod
import copy
import os
import ssl
import socket
import threading
import multiprocessing
import selectors
import enum
import logging
import logging.config
import logging.handlers
import asyncio
import requests
import json
import datetime
import ipaddress
import uuid
from pathlib import Path

from responder3.utils import ServerProtocol
from responder3.servers.BASE import ResponderServer, Result, LogEntry, Connection, EmailEntry

multiprocessing.freeze_support()

class TaskCmd(enum.Enum):
	STOP = 0
	PROCESS = 1

class Server():
	def __init__(self, ip, port, handler, rdnsd, proto = ServerProtocol.TCP, settings = None, sslsettings = None):
		self.bind_addr   = None
		self.bind_port   = None
		self.bind_family = None
		self.handler     = None
		self.settings    = None
		self.rdnsd       = None

		if ip in ['',None]:
			self.bind_addr = ipaddress.ip_address('0.0.0.0')
		else:
			self.bind_addr = ipaddress.ip_address(ip)

		self.bind_port = port
		self.bind_family = socket.AF_INET if self.bind_addr.version == 4 else socket.AF_INET6
		self.handler   = handler
		self.rdnsd     = rdnsd

		if settings is not None:
			self.settings  = copy.deepcopy(settings)

		if sslsettings is not None:
			if settings is None:
				self.settings = {}
			
			self.settings['SSL'] = copy.deepcopy(sslsettings)

		if proto is None:
			self.proto = ServerProtocol.TCP
			if self.settings is not None and 'SSL' in self.settings:
				self.proto = ServerProtocol.SSL
		elif isinstance(proto, ServerProtocol):
			self.proto = proto
		else:
			self.proto = ServerProtocol[proto]

	def getaddr(self):
		return ((self.bind_addr, self.bind_port))

class Task():
	def __init__(self, cmd, soc, handler, settings = None):
		self.cmd     = cmd
		self.soc     = soc
		self.handler = handler
		self.settings  = settings

class AsyncSocketServer(multiprocessing.Process):
	def __init__(self, server, resultQ):
		multiprocessing.Process.__init__(self)
		self.server    = server
		self.modulename = '%s-%d' % (self.server.handler.__name__, self.server.bind_port)
		self.resultQ   = resultQ
		self.loop      = None


	def log(self, level, message):
		self.resultQ.put(LogEntry(level, self.modulename, message))

	def setup(self):
		self.loop = asyncio.get_event_loop()
		if self.server.proto == ServerProtocol.TCP:
			s = self.server.handler()
			s._setup(self.server, self.loop, self.resultQ)
			s.run()
		elif self.server.proto == ServerProtocol.SSL:
			context = self.create_ssl_context()
			s = self.server.handler()
			s._setup(self.server, self.loop, self.resultQ)
			s.run(context)
		elif self.server.proto == ServerProtocol.UDP:
			s = self.server.handler()
			s._setup(self.server, self.loop, self.resultQ)
			s.run()
		else:
			raise Exception('Protocol not implemented!')

	def create_ssl_context(self):
		ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
		#ssl_context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION)
		#ssl_context.set_ciphers(self.server.settings['SSL']['ciphers'])
		ssl_context.load_cert_chain(certfile=self.server.settings['SSL']['certfile'], keyfile=self.server.settings['SSL']['keyfile'])
		#ssl_context.set_alpn_protocols(['http/1.1'])
		return ssl_context


	def run(self):
		self.log(logging.INFO,'Starting server!')
		self.setup()
		self.log(logging.INFO,'Server started on %s:%d!' % (self.server.bind_addr, self.server.bind_port))
		self.loop.run_forever()


class LogProcessor(multiprocessing.Process):
	def __init__(self, logsettings, resultQ, stopEvent):
		multiprocessing.Process.__init__(self)
		
		self.resultQ     = resultQ
		self.stopEvent   = stopEvent
		self.logsettings = logsettings

		self.logger = None
		self.extensionsQueues = []
		self.resultHistory = {}


	def log(self, level, message):
		self.handleLog(LogEntry(level, self.name, message))

	def setup(self):
		import importlib
		logging.config.dictConfig(self.logsettings['log'])
		for handler in self.logsettings['handlers']:
			try:
				handlerclassname  = '%sHandler' % self.logsettings['handlers'][handler]
				handlermodulename = 'responder3_log_%s' % handler.replace('-','_').lower()
				handlermodulename = '%s.%s' % (handlermodulename, handlerclassname)
				
				self.log(logging.DEBUG,'Importing handler module: %s , %s' % (handlermodulename,handlerclassname))
				handlerclass = getattr(importlib.import_module(handlermodulename), handlerclassname)

			except Exception as e:
				self.log(logging.ERROR,'Error importing module %s Reason: %s' % (handlermodulename, e) )
				continue

			try:
				tqueue = multiprocessing.Queue()
				self.extensionsQueues.append(tqueue)
				self.log(logging.DEBUG,'Lunching extention handler: %s' % (handlerclassname,))
				hdl = handlerclass(tqueue, self.resultQ, self.logsettings[self.logsettings['handlers'][handler]])
				hdl.start()
			except Exception as e:
				self.log(logging.ERROR,'Error creating class %s Reason: %s' % (handlerclassname, e) )
				continue
	
	def run(self):
		self.setup()		
		self.log(logging.INFO,'setup done')
		while not self.stopEvent.is_set():
			resultObj = self.resultQ.get()
			if isinstance(resultObj, Result):
				self.handleResult(resultObj)
			elif isinstance(resultObj, LogEntry):
				self.handleLog(resultObj)
			elif isinstance(resultObj, Connection):
				self.handleConnection(resultObj)
			elif isinstance(resultObj, EmailEntry):
				self.handleEmail(resultObj)
			else:
				raise Exception('Unknown object in queue! Got type: %s' % type(resultObj))

	def handleLog(self, log):
		logging.log(log.level, str(log))

	def handleConnection(self, con):
		logging.log(logging.INFO, str(con))
		t = {}
		t['type'] = 'Connection'
		t['data'] = con.toDict()
		for tqueue in self.extensionsQueues:
			tqueue.put(t)

	def handleResult(self, result):
		logging.log(logging.INFO, str(result.toDict()))
		if result.fingerprint not in self.resultHistory:
			self.resultHistory[result.fingerprint] = result
			t = {}
			t['type'] = 'Result'
			t['data'] = result.toDict()
			for tqueue in self.extensionsQueues:
				tqueue.put(t)
		else:
			self.log(logging.INFO,'Duplicate result found! Filtered.')

	def handleEmail(self, email):
		if 'writePath' in self.logsettings['email']:
			folder = Path(self.logsettings['email']['writePath'])
			filename = 'email_%s.eml' % str(uuid.uuid4())

			with open(str(folder.joinpath(filename).resolve()), 'wb') as f:
				f.write(email.email.as_bytes())
		
		self.log(logging.INFO,'You got mail!')

class LoggerExtension(ABC, threading.Thread):
	def __init__(self, resQ, logQ, config):
		threading.Thread.__init__(self)
		self.resQ = resQ
		self.logQ = logQ
		self.config = config
		self.logname = '%s-%s' % ('LogExt',self.modulename())
		

	def log(self, level, message):
		self.logQ.put(LogEntry(level, self.logname, message))

	def run(self):
		self.init(self.config)
		self.setup()
		self.log(logging.DEBUG,'Started!')
		self.main()
		self.log(logging.DEBUG,'Exiting!')

	@abstractmethod
	def init(self, config):
		pass

	@abstractmethod
	def main(self):
		pass

	@abstractmethod
	def modulename(self):
		pass

	@abstractmethod
	def setup(self):
		pass
				

class UniversalEncoder(json.JSONEncoder):
	def default(self, obj):
		if isinstance(obj, datetime.datetime):
			return obj.isoformat()
		elif isinstance(obj, enum.Enum):
			return obj.value
		else:
			return json.JSONEncoder.default(self, obj)