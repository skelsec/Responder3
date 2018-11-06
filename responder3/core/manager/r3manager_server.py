"""
TODO: this would need to be re-ported to use the generic websocket server to have a unified interface
"""

import asyncio
import websockets
import traceback
import uuid
import itertools


from responder3.core.manager.comms import *
from responder3.core.logtask import *
from responder3.core.gwss import *
from responder3.core.ssl import SSLContextBuilder

class Responder3ClientSession:
	def __init__(self, client_id, ws, log_queue, manager_log_queue, cmd_queue_in, cmd_queue_out, is_NATed = False):
		self.client_id = client_id
		self.ws = ws
		self.logger = Logger('Responder3ClientSession', logQ = log_queue)
		self.shutdown_evt = asyncio.Event()
		self.manager_log_queue = manager_log_queue
		self.cmd_queue_in = cmd_queue_in
		self.cmd_queue_out = cmd_queue_out
		self.is_NATed = False #indicates is the client is behind a NAT firewall, in that case we need to rely on the IP info of the client from the client itself
		
		self.remote_ip, self.remote_port = self.ws.remote_address
		self.remote_addr_s = '%s:%d' % (self.remote_ip, self.remote_port)
		self.classloader = R3ClientCommsClassLoader()

		
	@r3exception
	async def handle_commands_in(self):
		while True:
			cmd = await self.cmd_queue_in.get()
			try:
				await self.ws.send(cmd.to_json())
			except Exception as e:
				await self.logger.exception()
				self.shutdown_evt.set()
				return
		
	@r3exception
	async def handle_commands_out(self):
		while True:
			try:
				rply_data = await self.ws.recv()
			except Exception as e:
				await self.logger.exception()
				self.shutdown_evt.set()
				return
				
			try:
				msg = self.classloader.from_json(rply_data)
			except Exception as e:
				await self.logger.exception('Failed to parse incoming data!')
				continue
				
			if isinstance(msg, R3CliLog):
				if self.is_NATed == False:
					msg.remote_ip = self.remote_ip
					msg.remote_port = self.remote_port
				msg.client_id = self.client_id
				await self.manager_log_queue.put(msg)
			
			elif isinstance(msg, (R3CliServerStopRply, R3CliListServersRply, R3CliCreateServerRply, R3CliListInterfacesRply)):
				msg.client_id = self.client_id
				await self.cmd_queue_out.put(msg)
				
			else:
				await self.logger.info('Client sent unknown message! %s' % type(msg))		
		
	@r3exception
	async def run(self):
		asyncio.ensure_future(self.handle_commands_in())
		asyncio.ensure_future(self.handle_commands_out())
		await self.cmd_queue_in.put(R3CliListInterfacesCmd())
			
		await self.shutdown_evt.wait()
	

class Responder3ManagerServer:
	def __init__(self, listen_ip, listen_port, config, log_queue, manager_log_queue, cmd_q_in, cmd_q_out, shutdown_evt, ssl_ctx = None):
		self.config = config
		self.logger = Logger('Responder3ManagerServer', logQ = log_queue)
		self.manager_log_queue = manager_log_queue #works in one way only, to inject log messages from remote clients
		self.cmd_q_in = cmd_q_in #commands from the server manager to the clients
		self.cmd_q_out = cmd_q_out #command results from clients to server manager
		self.shutdown_evt = shutdown_evt #asnycio.Event to signal shutdown of the server
		
		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.ssl_ctx = ssl_ctx
		if self.ssl_ctx:
			self.ssl_ctx = SSLContextBuilder.from_dict(ssl_ctx)
		
		self.clients = {} #client_id -> Responder3ClientSession
		
		
	@r3exception
	async def client_handler(self, ws, path):
		################################################################################
		#!!!! If you see an error here, websockets library might have changed
		#By default the library doesnt offer high-level api to grab the client certificate
		#Check the new documentation of websockets if error comes in here!
		client_cert = ws.writer.get_extra_info('peercert') 
		################################################################################
		if not client_cert:
			client_id = str(uuid.uuid4()) #change this to ssl CN of the client!
		else:
			#https://stackoverflow.com/questions/50548709/cant-receive-tls-certificate-using-getpeercert-ssl-certificate-verify-failed
			#I have no idea how this works tho
			client_id = dict(itertools.chain(*client_cert["subject"]))["commonName"]
		
		await self.logger.info('[%s] connected from %s' % (client_id, '%s:%d' % ws.remote_address))
		
		client_cmd_queue = asyncio.Queue()
		cs = Responder3ClientSession(client_id, ws, self.logger.logQ, self.manager_log_queue, client_cmd_queue, self.cmd_q_out)
		self.clients[client_id] = cs
		await cs.run()
		del self.clients[client_id]
		await self.logger.info('[%s] disconnected' % client_id)
		
		
		
	@r3exception
	async def run(self):
		server = await websockets.serve(self.client_handler, self.listen_ip, self.listen_port, ssl=self.ssl_ctx)
		await server.wait_closed()
		
		

		
if __name__ == '__main__':
	async def print_cmd_queue(cmd_q_out):
		while True:
			cmd = await cmd_q_out.get()
			print('print_cmd_queue')
			print(cmd)
		
	config = {}
	logger = Logger('Responder3ManagerServer')
	manager_log_queue = asyncio.Queue()
	cmd_q_in = asyncio.Queue()
	cmd_q_out = asyncio.Queue()
	shutdown_evt = asyncio.Queue()
	
	r3m = Responder3ManagerServer(config, logger, manager_log_queue, cmd_q_in, cmd_q_out, shutdown_evt)
	
	asyncio.ensure_future(logger.run())
	asyncio.ensure_future(print_cmd_queue(cmd_q_out))
	loop = asyncio.get_event_loop()	
	loop.run_until_complete(r3m.run())
	
	
	
	
	
	
	
	
