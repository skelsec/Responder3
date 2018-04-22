import os
from abc import ABC, abstractmethod
import threading
import multiprocessing
import logging
import logging.config
import traceback
import sys
import importlib
import uuid
from pathlib import Path
import io

from responder3.core.commons import *


class LogProcessor(multiprocessing.Process):
	def __init__(self, logsettings, logQ):
		"""
		Extensible logging process. Does the logging via python's built-in logging module.
		:param logsettings: Dictionary describing the logging settings
		:type logsettings: dict
		:param logQ: Queue to read logging messages from
		:type logQ: multiprocessing.Queue
		"""
		multiprocessing.Process.__init__(self)
		self.logsettings = logsettings
		self.resultQ     = logQ
		self.logger      = None
		self.extensionsQueues = []
		self.resultHistory = {}
		self.proxyfilehandler = None

	def log(self, message, level = logging.INFO):
		"""
		Logging function used to send logs in this process only!
		:param message: The message to be logged
		:type message: str
		:param level: log level
		:type level: int
		:return: None
		"""
		self.handle_log(LogEntry(level, self.name, message))

	def setup(self):
		"""
		Parses the settings dict and populates the necessary variables
		:return: None
		"""
		logging.config.dictConfig(self.logsettings['log'])
		self.logger = logging.getLogger('Responder3')

		if 'logproxydata' in self.logsettings:
			self.proxyfilehandler = open(self.logsettings['logproxydata']['filepath'], 'ab')

		if 'handlers' in self.logsettings:
			for handler in self.logsettings['handlers']:
				try:
					if handler == 'TEST':
						print('TEST!')
						handlerclass = TestExtension
						handlerclassname = 'TEST'
					else:
						handlerclassname  = '%sHandler' % self.logsettings['handlers'][handler]
						handlermodulename = 'responder3_log_%s' % handler.replace('-','_').lower()
						handlermodulename = '%s.%s' % (handlermodulename, handlerclassname)

						self.log('Importing handler module: %s , %s' % (handlermodulename, handlerclassname), logging.DEBUG)
						handlerclass = getattr(importlib.import_module(handlermodulename), handlerclassname)

				except Exception as e:
					self.log('Error importing module %s Reason: %s' % (handler, e), logging.ERROR)
					continue

				try:
					tqueue = multiprocessing.Queue()
					self.extensionsQueues.append(tqueue)
					self.log('Lunching extention handler: %s' % (handlerclassname,), logging.DEBUG)
					hdl = handlerclass(tqueue, self.resultQ, self.logsettings[self.logsettings['handlers'][handler]])
					hdl.start()
				except Exception as e:
					self.log_exception('Error creating class %s Reason: %s' % (handlerclassname, e))
					continue
	
	def run(self):
		try:
			self.setup()		
			self.log('setup done', logging.DEBUG)
			while True:
				result = self.resultQ.get()
				for tqueue in self.extensionsQueues:
					self.log('sent')
					tqueue.put(result)
				if isinstance(result, Credential):
					self.handle_credential(result)
				elif isinstance(result, LogEntry):
					self.handle_log(result)
				elif isinstance(result, Connection):
					self.handle_connection(result)
				elif isinstance(result, EmailEntry):
					self.handle_email(result)
				elif isinstance(result, PoisonResult):
					self.handle_poisonresult(result)
				elif isinstance(result, ProxyData):
					self.handle_proxydata(result)
				else:
					raise Exception('Unknown object in queue! Got type: %s' % type(result))
		except KeyboardInterrupt:
			sys.exit(0)
		except Exception as e:
			traceback.print_exc()
			self.log('Main loop exception!', logging.ERROR)
		finally:
			if self.proxyfilehandler is not None:
				try:
					self.proxyfilehandler.close()
				except:
					pass

	def handle_log(self, log):
		"""
		Handles the messages of log type
		:param log: Log message object
		:type log: LogEntry
		:return: None
		"""
		self.logger.log(log.level, str(log))

	def handle_connection(self, con):
		"""
		Handles the messages of log type
		:param con: Connection message object
		:type con: Connection
		:return: None
		"""
		self.logger.log(logging.INFO, str(con))

	def handle_credential(self, result):
		"""
		Logs credential object arriving from logqueue
		:param result: Credential object to log
		:type result: Credential
		:return: None
		"""
		if result.fingerprint not in self.resultHistory:
			logging.log(logging.INFO, str(result.to_dict()))
			self.resultHistory[result.fingerprint] = result
		else:
			self.log('Duplicate result found! Filtered.')

	def handle_email(self, email):
		"""
		Logs the email object arriving from logqueue
		:param email: Email object to log
		:type email: Email
		:return:
		"""
		if 'writePath' in self.logsettings['email']:
			folder = Path(self.logsettings['email']['writePath'])
			filename = 'email_%s.eml' % str(uuid.uuid4())

			with open(str(folder.joinpath(filename).resolve()), 'wb') as f:
				f.write(email.email.as_bytes())
		
		self.log('You got mail!')

	def handle_poisonresult(self, poisonresult):
		"""
		Logs the poisonresult object arriving from logqueue
		:param poisonresult:
		:type poisonresult: PoisonResult
		:return: None
		"""
		self.log(repr(poisonresult))

	def handle_proxydata(self, proxydata):
		# TODO: currently it flushes everything on each line, this is not good (slow)
		# need to write a better scheduler for outout, timer maybe?
		"""
		Writes the incoming proxydata to a file
		:param proxydata: ProxyData
		:type proxydata: ProxyData
		:return: None
		"""
		if self.proxyfilehandler is not None:
			try:
				self.proxyfilehandler.write(proxydata.to_json().encode() + b'\r\n')
				self.proxyfilehandler.flush()
				os.fsync(self.proxyfilehandler.fileno())
			except Exception as e:
				self.log_exception('Error writing proxy data to file!')
				return

	# this function is a duplicate, clean it up!
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


class LoggerExtension(ABC, threading.Thread):
	def __init__(self, resQ, logQ, config):
		threading.Thread.__init__(self)
		self.resQ = resQ
		self.logQ = logQ
		self.config = config
		self.modulename = '%s-%s' % ('LogExt', self.__class__.__name__)

	def run(self):
		try:
			self.init()
			self.setup()
			self.log('Started!', logging.DEBUG)
			self.main()
			self.log('Exiting!', logging.DEBUG)
		except Exception:
			self.log_exception('Exception in main function!')

	@abstractmethod
	def init(self):
		pass

	@abstractmethod
	def main(self):
		pass

	@abstractmethod
	def setup(self):
		pass

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


class TestExtension(LoggerExtension):
	def init(self):
		self.output_queue = self.config['output_queue']

	def setup(self):
		pass

	def main(self):
		while True:
			result = self.resQ.get()
			self.output_queue.put(result)


