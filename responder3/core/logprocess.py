import os
from abc import ABC, abstractmethod
import threading
import multiprocessing
import logging
import logging.config
import traceback
import sys
import importlib

from responder3.core.commons import *

class LogProcessor(multiprocessing.Process):
	def __init__(self, logsettings, logQ):
		multiprocessing.Process.__init__(self)
		self.logsettings = logsettings
		self.resultQ     = logQ
		self.logger      = None
		self.extensionsQueues = []
		self.resultHistory = {}
		self.proxyfilehandler = None


	def log(self, message, level = logging.INFO):
		self.handleLog(LogEntry(level, self.name, message))

	def setup(self):
		logging.config.dictConfig(self.logsettings['log'])
		self.logger = logging.getLogger('Responder3')

		if 'logproxydata' in self.logsettings:
			self.proxyfilehandler = open(self.logsettings['logproxydata']['filepath'], 'ab')
		

		if 'handlers' in self.logsettings:
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
		try:
			self.setup()		
			self.log('setup done', logging.DEBUG)
			#while not self.stopEvent.is_set():
			while True:
				resultObj = self.resultQ.get()
				if isinstance(resultObj, Credential):
					self.handleCredential(resultObj)
				elif isinstance(resultObj, LogEntry):
					self.handleLog(resultObj)
				elif isinstance(resultObj, Connection):
					self.handleConnection(resultObj)
				elif isinstance(resultObj, EmailEntry):
					self.handleEmail(resultObj)
				elif isinstance(resultObj, PoisonResult):
					self.handlePoisonResult(resultObj)
				elif isinstance(resultObj, ProxyData):
					self.handleProxyData(resultObj)
				else:
					raise Exception('Unknown object in queue! Got type: %s' % type(resultObj))
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

	def handleLog(self, log):
		self.logger.log(log.level, str(log))

	def handleConnection(self, con):
		self.logger.log(log.level, str(con))
		t = {}
		t['type'] = 'Connection'
		t['data'] = con.toDict()
		for tqueue in self.extensionsQueues:
			tqueue.put(t)

	def handleCredential(self, result):
		if result.fingerprint not in self.resultHistory:
			logging.log(logging.INFO, str(result.toDict()))
			self.resultHistory[result.fingerprint] = result
			t = {}
			t['type'] = 'Credential'
			t['data'] = result.toDict()
			for tqueue in self.extensionsQueues:
				tqueue.put(t)
		else:
			self.log('Duplicate result found! Filtered.')

	def handleEmail(self, email):
		if 'writePath' in self.logsettings['email']:
			folder = Path(self.logsettings['email']['writePath'])
			filename = 'email_%s.eml' % str(uuid.uuid4())

			with open(str(folder.joinpath(filename).resolve()), 'wb') as f:
				f.write(email.email.as_bytes())
		
		self.log('You got mail!')

	def handlePoisonResult(self, poisonResult):
		self.log(repr(poisonResult))

	def handleProxyData(self, proxydata):
		#TODO: currently it flushes everything on each line, this is not good (slow)
		#need to write a better scheduler for outout, timer maybe?
		if self.proxyfilehandler is not None:
			try:
				self.proxyfilehandler.write(proxydata.toJSON().encode() + b'\r\n')
				self.proxyfilehandler.flush()
				os.fsync(self.proxyfilehandler.fileno())
			except Exception as e:
				self.logexception('Error writing proxy data to file!')
				return

	#this function is a duplicate, clean it up!
	def logexception(self, message = None):
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