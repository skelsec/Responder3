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
import json
import datetime
import ipaddress
import uuid
from pathlib import Path

from responder3.core.common import *
from responder3.utils import ServerProtocol
from responder3.core.servertemplate import ResponderServer, Result, Connection, EmailEntry, PoisonResult


multiprocessing.freeze_support()


class AsyncSocketServer(multiprocessing.Process):
	def __init__(self, server):
		multiprocessing.Process.__init__(self)
		self.server     = server
		self.modulename = '%s-%d' % (self.server.handler.__name__, self.server.bind_port)
		self.loop       = None
		self.logQueue   = get_logQueue()


	def log(self, level, message):
		self.logQueue.put(LogEntry(level, self.modulename, message))

	def setup(self):
		self.loop = asyncio.get_event_loop()
		if self.server.proto == ServerProtocol.TCP:
			s = self.server.handler()
			s._setup(self.server, self.loop)
			s.run()
		elif self.server.proto == ServerProtocol.SSL:
			context = self.create_ssl_context()
			s = self.server.handler()
			s._setup(self.server, self.loop)
			s.run(context)
		elif self.server.proto == ServerProtocol.UDP:
			s = self.server.handler()
			s._setup(self.server, self.loop)
			s.run()
		else:
			raise Exception('Protocol not implemented!')

	def create_ssl_context(self):
		#TODO: enable additional fine-tuning of the SSL context from config file
		ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
		#ssl_context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION)
		#ssl_context.set_ciphers(self.server.settings['SSL']['ciphers'])
		ssl_context.load_cert_chain(certfile=self.server.settings['SSL']['certfile'], keyfile=self.server.settings['SSL']['keyfile'])
		#ssl_context.set_alpn_protocols(['http/1.1'])
		return ssl_context


	def run(self):
		self.log(logging.DEBUG,'Starting server!')
		self.setup()
		self.log(logging.INFO,'Server started on %s:%d!' % (self.server.bind_addr, self.server.bind_port))

		try:
			self.loop.run_forever()
		except KeyboardInterrupt:
			return