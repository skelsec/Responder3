import logging
import traceback
import sys
import io
import asyncio

from responder3.core.logging.log_objects import *
from responder3.core.commons import Connection, ConnectionStatus

class Logger:
	"""
	This class is used to provie a better logging experience for asyncio based classes/functions
	Probably will replace logtask "solution" with this one in the future
	TODO
	"""
	def __init__(self, name, logger = None, logQ = None, level = logging.DEBUG, connection = None):
		self.level = level
		self.consumers = {}
		self.logger = logger
		self.name = name
		self._connection = connection

		self.is_final = True
		if logQ:
			self.logQ = logQ
			self.is_final = False
		else:
			self.logQ = asyncio.Queue()
		
	async def run(self):
		"""
		you only need to call this function IF the logger instance is the final dst!
		Also, consumers will not work if this is not the final one!
		"""
		if self.is_final == False:
			return
		try:
			while True:
				logmsg = await self.logQ.get()
				await self.handle_logger(logmsg)
				if len(self.consumers) > 0:
					await self.handle_consumers(logmsg)
		
		except Exception as e:
			print('Logger run exception! %s' % e)
			
	async def handle_logger(self, msg):
		print('%s %s %s %s' % (datetime.datetime.utcnow().isoformat(), self.name, level, msg))
		
	async def handle_consumers(self, msg):
		try:
			for consumer in self.consumers:
				await consumer.process_log(msg)
		except Exception as e:
			print(e)
			
	async def debug(self, msg):
		await self.logQ.put(LogEntry(logging.DEBUG, self.name, msg, self._connection))
		
	async def info(self, msg):
		await self.logQ.put(LogEntry(logging.INFO, self.name, msg, self._connection))
	
	async def exception(self, message = None):
		sio = io.StringIO()
		ei = sys.exc_info()
		tb = ei[2]
		traceback.print_exception(ei[0], ei[1], tb, None, sio)
		msg = sio.getvalue()
		if msg[-1] == '\n':
			msg = msg[:-1]
		sio.close()
		if message is not None:
			msg = '%s : %s' % (message,msg)
		await self.logQ.put(LogEntry(logging.ERROR, self.name, msg, self._connection))
			
	async def error(self, msg):
		await self.logQ.put(LogEntry(logging.ERROR, self.name, msg, self._connection))
		
	async def warning(self, msg):
		await self.logQ.put(LogEntry(logging.WARNING, self.name, msg, self._connection))
		
	async def log(self, level, msg):
		"""
		Level MUST be bigger than 0!!!
		"""
		await self.logQ.put(LogEntry(level, self.name, msg, self._connection))

	async def connection(self, connection, status):
		"""
		Logs incoming connection
		:param connection: The Connection object to log
		:type connection: Connection
		:param status: Connection status
		:type: ConnectionStatus
		:return: None
		"""
		if status == ConnectionStatus.OPENED or status == ConnectionStatus.STATELESS:
			#await self.info('New connection opened from %s:%d' % (connection.remote_ip, connection.remote_port))
			co = ConnectionOpened(connection, self.name)
			await self.logQ.put(co)
			
		elif status == ConnectionStatus.CLOSED:
			#await self.info('Connection closed by %s:%d' % (connection.remote_ip, connection.remote_port))
			cc = ConnectionClosed(connection, self.name)
			await self.logQ.put(cc)

	async def credential(self, credential):
		"""
		Create a credential message and send it to the LogProcessor for procsesing
		"""
		credential.module = self.name
		credential.connection = self._connection
		credential.client_addr = self._connection.remote_ip
		credential.client_rdns = self._connection.remote_dns
		await self.logQ.put(credential)

	"""
	async def log_poisonresult(self, requestName = None, poisonName = None, poisonIP = None):
		pr = PoisonResult()
		pr.module = self.server_name
		pr.target = self.session.connection.remote_ip
		pr.request_name = requestName
		pr.request_type = None
		pr.poison_name = poisonName
		pr.poison_addr = poisonIP
		pr.mode = self.settings['mode']

		await self.logger.poisonresult(credential)

	async def log_email(self, emailEntry):
		await self.logger.email(emailEntry)
	"""

	async def traffic(self, traffic):
		traffic.module = self.name
		traffic.connection = self._connection
		await self.logQ.put(traffic)

	async def proxylog(pl):
		pl.module = self.name
		pl.connection = self._connection
		await self.logQ.put(pl)

	async def proxydata(proxydata):
		proxydata.module = self.name
		proxydata.connection = self._connection
		await self.logQ.put(proxydata)

		
	def add_consumer(self, consumer):
		self.consumers[consumer] = 0
		
	def del_consumer(self, consumer):
		if consumer in self.consumers:
			del self.consumers[consumer]
			
			
def r3exception(funct):
	"""
	Decorator for handling exceptions
	Use it with the Logger class only!!!
	"""
	async def wrapper(*args, **kwargs):
		this = args[0] #renaming self to 'this'
		try:
			t = await funct(*args, **kwargs)
			return t
		except Exception as e:
			await this.logger.exception(funct.__name__)
			return
			
	return wrapper

def r3trafficlogexception(funct):
	"""
	Decorator for handling exceptions
	Use it with the Logger class only!!!
	"""
	async def wrapper(*args, **kwargs):
		this = args[0] #renaming self to 'this'
		try:
			t = await funct(*args, **kwargs)
		except asyncio.CancelledError:
			await this.logger.debug('Got cancelled! Probably timeout')
		except:				
			await this.logger.exception(funct.__name__)
			traffic_in  = await this.creader.log_comms()
			traffic_out = await this.cwriter.log_comms()
			traffic_in.data_sent = traffic_out.data_sent
			await this.logger.traffic(traffic_in)

			if hasattr(this, 'shutdown_evt') == True:
				this.shutdown_evt.set()
			
			return
			
	return wrapper