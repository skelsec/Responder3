import websockets
import asyncio


from responder3.core.manager.comms import *
from responder3.core.logging.logger import *
from responder3.core.gwss import *
from responder3.core.ssl import SSLContextBuilder

class Responder3ManagerClient:
	def __init__(self, server_url, config, log_queue, manager_log_queue, cmd_q_in, cmd_q_out, shutdown_evt, ssl_ctx = None):
		self.config = config
		self.logger = Logger('Responder3ManagerClient', logQ = log_queue)
		self.manager_log_queue = manager_log_queue #log_queue (asyincio.Queue) that yield all the log messages the responder3 instance has
		self.cmd_q_in = cmd_q_in #commands from the server manager to the clients
		self.cmd_q_out = cmd_q_out #command results from clients to server manager
		self.shutdown_evt = shutdown_evt #asnycio.Event to signal shutdown of the server
		self.shutdown_session_evt = asyncio.Event() #asnycio.Event to signal shutdown of the server
		
		self.server_url = server_url
		self.ssl_ctx = ssl_ctx
		if self.ssl_ctx:
			self.ssl_ctx = SSLContextBuilder.from_dict(ssl_ctx)
		
		self.classloader = R3ClientCommsClassLoader()
		self.ws = None
		
	@r3exception
	async def handle_logs(self):
		"""
		Waits for logs coming form the log queue, wraps them in R3CliLog object and sends them to the manager
		"""
		while not self.shutdown_session_evt.is_set():
			log_obj = await self.manager_log_queue.get()
			log_obj_type = logobj2type_inv[type(log_obj)]
			await self.send_msg(R3CliLog(log_obj_type = log_obj_type, log_obj = log_obj))
			
	@r3exception
	async def handle_incoming_commands(self):
		while not self.shutdown_session_evt.is_set():
			try:
				cmd_data = await self.ws.recv()
			except Exception as e:
				self.shutdown_session_evt.set()
				raise e
			
			print('Command in! %s' % cmd_data)
			cmd = self.classloader.from_json(cmd_data)
			print(cmd)
			await self.cmd_q_in.put(cmd)
	
	@r3exception 
	async def handle_outgoing_replies(self):
		while not self.shutdown_session_evt.is_set():
			rply = await self.cmd_q_out.get()
			print(rply)
			await self.send_msg(rply)
		
	@r3exception
	async def send_msg(self, msg):
		msg.remote_ip = 'test'
		msg.remote_port = 0
		try:
			await self.ws.send(msg.to_json())
		except Exception as e:
			self.shutdown_session_evt.set()
			raise e
			
			
	@r3exception
	async def run(self):
		while not self.shutdown_evt.is_set():
			try:
				self.shutdown_session_evt.clear()
				await self.logger.info('Connecting to manager server...')
				async with websockets.connect(self.server_url, ssl = self.ssl_ctx) as ws:
					self.ws = ws
					await self.logger.info('Connected to manager server!')
					asyncio.ensure_future(self.handle_logs())
					asyncio.ensure_future(self.handle_incoming_commands())
					asyncio.ensure_future(self.handle_outgoing_replies())
					await self.shutdown_session_evt.wait()
					await asyncio.sleep(1)
			except Exception as e:
				await self.logger.exception()
				pass
			
			await asyncio.sleep(5)
			
		
if __name__ == '__main__':
	config = {}
	logger = Logger('Responder3ManagerServer')
	manager_log_queue = asyncio.Queue()
	cmd_q_in = asyncio.Queue()
	cmd_q_out = asyncio.Queue()
	shutdown_evt = asyncio.Event()
	server_url = 'ws://127.0.0.1:9191'
	
	r3c = Responder3ManagerClient(server_url, config, logger, manager_log_queue, cmd_q_in, cmd_q_out, shutdown_evt)
	
	loop = asyncio.get_event_loop()
	asyncio.ensure_future(logger.run())
	loop.run_until_complete(r3c.run())
	