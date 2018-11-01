# Work with Python 3.6
"""
Generic websocket based client-server framework
For logging it uses the Logger object and the r3exception decorators

Idea was to provide a common interface for remote communications where devs
do not need to deal with teh actual server-client comms.


Client reads a queue for !strings! and dispatches it to the server
Server waits for incoming clients, and dispatches all incoming messages to a queue as GWSSPacket

When cert-auth based SSL is set up via the SSL-CTX parameters, 
the server will yield the client's cerificate to the output queue

Current: One-way comms
The server is only capable of retrieving messages
The client is only capable of sending messages

TODO: Make it two-way comms

"""
import asyncio
import websockets
import uuid

from responder3.core.logtask import *
from responder3.core.commons import *

class GWSSPacket:
	def __init__(self, client_ip, client_port, data, client_cert = None):
		self.client_ip = client_ip
		self.client_port = client_port
		self.client_cert = client_cert
		self.data = data
		
	def get_addr_s(self):
		return '%s:%d' % (self.client_ip, self.client_port)

class GenericWSPacket:
	def __init__(self, data):
		self.data = data #must be string!!!
		
	def to_dict(self):
		t = {}
		t['data'] = self.data
		return t
		
	def to_json(self):
		return json.dumps(self.to_dict())
		
	@staticmethod
	def from_dict(d):
		data = d['data']
		return GenericWSPacket(data)
		
	@staticmethod
	def from_json(raw_data):
		return GenericWSPacket.from_dict(json.loads(raw_data))

class GenericWSClient:
	def __init__(self, logQ, server_url, out_queue, ssl_ctx = None):
		self.logger = Logger('GenericWSClient', logQ = logQ)
		self.server_url = server_url
		self.ssl_ctx = ssl_ctx
		self.out_queue = out_queue
		self.shutdown_evt = asyncio.Event() #to completely shutdown the client
		self.shutdown_session_evt = asyncio.Event() #to disconnect from server, and try to connect back
		
		self.ws_ping_interval = 5
		
	@r3exception
	async def keepalive(self, ws):
		await self.logger.debug('Keepalive running!')
		while not self.shutdown_session_evt.is_set():
			try:
				pong_waiter = await ws.ping()
				await asyncio.sleep(self.ws_ping_interval)
			except websockets.exceptions.ConnectionClosed:
				await self.logger.debug('Server disconnected!')
				self.shutdown_session_evt.set()
				continue
				
			except Exception as e:
				await self.logger.exception('Unexpected error!')
				self.shutdown_session_evt.set()
				continue
	
	@r3exception
	async def run(self):
		while not self.shutdown_evt.is_set():
			try:
				self.shutdown_session_evt.clear()
				await self.logger.debug('Connecting to server...')
				async with websockets.connect(self.server_url, ssl=self.ssl_ctx) as ws:
					await self.logger.debug('Connected to server!')
					asyncio.ensure_future(self.keepalive(ws))
					while not self.shutdown_session_evt.is_set():
						try:
							#waiting to get a log from the log queue, timeout is introducted so we can check 
							#in the while loop above is the ws still exists
							str_data = await asyncio.wait_for(self.out_queue.get(), 1)
						except asyncio.TimeoutError:
							continue
						except:
							await self.logger.exception()
							
						try:
							packet = GenericWSPacket(str_data)
							await ws.send(packet.to_json())
						except Exception as e:
							self.shutdown_session_evt.set()
							raise e
						
						
				await self.logger.debug('Disconnecte from remote ws logger!')
			except Exception as e:
				await self.logger.exception()
				pass
			
			await asyncio.sleep(5)
			
class GenericWSServer:
	def __init__(self, logQ, listen_ip, listen_port, queue_in, ssl_ctx = None):
		self.logger = Logger('GenericWSServer', logQ = logQ)
		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.ssl_ctx = ssl_ctx
		self.queue_in = queue_in
		self.shutdown_evt = asyncio.Event()
		self.shutdown_session_evt = asyncio.Event()
		self.classloader = R3ClientCommsClassLoader()
		
		self.clients = {} #client_id -> Responder3ClientSession
		self.ws_ping_interval = 5
	
	@r3exception
	async def keepalive(self, ws):
		await self.logger.debug('Keepalive running!')
		while not self.shutdown_session_evt.is_set():
			try:
				pong_waiter = await ws.ping()
				await asyncio.sleep(self.ws_ping_interval)
			except websockets.exceptions.ConnectionClosed:
				await self.logger.debug('Client disconnected!')
				self.shutdown_session_evt.set()
				continue
				
			except Exception as e:
				await self.logger.exception('Unexpected error!')
				self.shutdown_session_evt.set()
				continue
	
	@r3exception
	async def client_handler(self, ws, path):
		client_ip, client_port = ws.remote_address
		################################################################################
		#!!!! If you see an error here, websockets library might have changed
		#By default the library doesnt offer high-lvel api to grab the client certificate
		#Check the new documentation of websockets if error comes in here!
		client_cert = ws.writer.get_extra_info('peercert') 
		################################################################################
		
		asyncio.ensure_future(self.keepalive(ws))
		
		client_id = str(uuid.uuid4()) #change this to ssl CN of the client!
		
		await self.logger.info('[%s] connected from %s' % (client_id, '%s:%d' % ws.remote_address))
		
		self.clients[client_id] = ws
		while not self.shutdown_session_evt.is_set():
			try:
				packet_raw = await ws.recv()
			except Exception as e:
				await self.logger.exception()
				self.shutdown_session_evt.set()
				continue
			
			packet = GenericWSPacket.from_json(packet_raw)
			gp = GWSSPacket(client_ip, client_port, packet.data, client_cert = client_cert)
			await self.queue_in.put(gp)
			
			
		del self.clients[client_id]
		await self.logger.info('[%s] disconnected' % client_id)
		
	async def run(self):
		server = await websockets.serve(self.client_handler, self.listen_ip, self.listen_port, ssl=self.ssl_ctx)
		await server.wait_closed()