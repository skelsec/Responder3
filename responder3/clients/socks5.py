import traceback
import logging
import io
import os
import copy
import time
import asyncio
from random import shuffle
from urllib.parse import urlparse
import ipaddress

from responder3.core.commons import *
from responder3.core.sockets import setup_base_socket
from responder3.core.serverprocess import ServerProperties
from responder3.core.interfaceutil import interfaces
from responder3.protocols.SOCKS5 import *


class SOCKS5ServerConfig:
	def __init__(self):
		self.ip       = ''
		self.port     = ''
		self.timeout  = ''
		self.username = ''
		self.password = ''

	def __repr__(self):
		t  = '== SOCKS5ServerConfig ==\r\n'
		t += 'IP: %s\r\n' % self.ip
		t += 'port: %s\r\n' % self.port
		t += 'timeout: %s\r\n' % self.timeout
		t += 'username: %s\r\n' % self.username
		t += 'password: %s\r\n' % self.password
		return t

	def get_addr(self):
		return str(self.ip), self.port

	def get_paddr(self):
		return '%s:%d' % (str(self.ip), self.port)

	@staticmethod
	def from_url(url, timeout = 10):
		conf = SOCKS5ServerConfig()
		o = urlparse(url)

		if o.scheme.lower() != 'socks5':
			raise Exception('Only SOCKS5 proxies are supported! (usage: socks5://<user>:<pass>@ip:port')

		conf.ip = o.netloc
		if conf.ip.find('@') != -1:
			conf.ip = conf.ip.split('@')[1]

		if conf.ip.find(':') != -1:
			m = conf.ip.rfind(':')
			conf.ip = conf.ip[:m]

		if o.port is None:
			logging.debug('No port specified, default port will be used (1080)')
			conf.port = 1080
		else:
			conf.port = o.port
		conf.timeout = timeout
		conf.username = o.username
		conf.password = o.password

		return conf

	@staticmethod
	def construct(ip, port, timeout = 1, username = None, password = None):
		conf = SOCKS5ServerConfig()
		conf.ip       = ip
		conf.port     = int(port)
		conf.timeout  = int(timeout)
		conf.username = username
		conf.password = password
		return conf

	@staticmethod
	def from_json(s):
		return SOCKS5ServerConfig.from_dict(json.loads(s))

	@staticmethod
	def from_dict(d):
		s = SOCKS5ServerConfig()
		s.ip       = ipaddress.ip_address(d['ip'])
		s.port     = int(d['port'])
		s.timeout  = int(d['timeout'])
		s.username = d['username']
		s.password = d['password']
		return s

class Socks5Client:
	def __init__(self):
		self.servers = None
		self.bind_addr = None
		self.bind_port = None
		self.remote_addr = None
		self.remote_port = None
		self.target = None
		self.randomize_servers = False
		self.cmdparser = SOCKS5SocketParser()
		self.listener_socket_config = None

		self.latest_tunnel = None
		self.server_props = None
		self.server_coro = None
		self.clients = {}
		self.loop = asyncio.get_event_loop()
		self.timeout = None


	@asyncio.coroutine
	def generic_read(self, reader):
		return reader.read(1024)

	@asyncio.coroutine
	def proxy_forwarder(self, reader, writer, reader_address, stop_event, timeout = None):
		reader_address = '%s:%d' % reader_address
		writer_address = '%s:%d' % writer.get_extra_info('peername')
		logging.debug('Proxy starting %s -> %s' % (reader_address, writer_address))
		while not stop_event.is_set():
			try:
				data = yield from asyncio.wait_for(self.generic_read(reader), timeout=timeout)
			except asyncio.TimeoutError:
				logging.exception()
				stop_event.set()
				break

			if data == b'' or reader.at_eof():
				logging.debug('Connection closed!')
				stop_event.set()
				break

			logging.log(1, '%s -> %s: %s' % (reader_address, writer_address, data.hex()))

			try:
				writer.write(data)
				yield from asyncio.wait_for(writer.drain(), timeout=timeout)
			except asyncio.TimeoutError:
				logging.debug('Remote server timed out!')
				stop_event.set()
				break

		return

	def create_listener_socket_config(self):
		try:
			self.listener_socket_config = setup_base_socket(self.server_props)
			#self.listener_socket_config.listen(500)
		except Exception as e:
			raise e

	@asyncio.coroutine
	def connect_proxy(self, serverconfig):
		print('Connecting to socks5 proxy %s:%d...' % serverconfig.get_addr())
		try:
			reader, writer = yield from asyncio.wait_for(
				asyncio.open_connection(
					host=serverconfig.ip,
					port=serverconfig.port
				),
				timeout=10
			)
			return reader, writer

		except Exception as e:
			logging.exception('Failed to connect to proxy!')

	@asyncio.coroutine
	def create_tunnel(self, target, server, proxy_reader, proxy_writer):
		logging.info('Establishing proxy connection %s => %s' % (server.get_paddr(), target.get_paddr()))
		authmethods = [SOCKS5Method.NOAUTH]
		if server.username is not None:
			authmethods.append(SOCKS5Method.PLAIN)

		logging.debug('Sending negotiation command to %s:%d' % proxy_writer.get_extra_info('peername'))
		proxy_writer.write(SOCKS5Nego.construct(authmethods).to_bytes())
		t = yield from asyncio.wait_for(proxy_writer.drain(), timeout = 1)

		rep_nego = yield from asyncio.wait_for(SOCKS5NegoReply.from_streamreader(proxy_reader), timeout = self.timeout)
		logging.debug('Got negotiation reply from %s: %s' % (proxy_writer.get_extra_info('peername'), repr(rep_nego)))
		if rep_nego.METHOD == SOCKS5Method.NOTACCEPTABLE:
			raise Exception('Failed to connect to proxy %s:%d! No common authentication type!' % proxy_writer.get_extra_info('peername'))

		if rep_nego.METHOD == SOCKS5Method.PLAIN:
			logging.debug('Preforming plaintext auth to %s:%d' % proxy_writer.get_extra_info('peername'))
			proxy_writer.write(SOCKS5PlainAuth.construct(server.username, server.password).to_bytes())
			t = yield from asyncio.wait_for(proxy_writer.drain(), timeout=1)
			rep_auth_nego = yield from asyncio.wait_for(SOCKS5NegoReply.from_streamreader(proxy_reader), timeout = self.timeout)

			if rep_auth_nego.METHOD != SOCKS5Method.NOAUTH:
				raise Exception('Failed to connect to proxy %s:%d! Authentication failed!' % proxy_writer.get_extra_info('peername'))

		logging.debug('Sending connect request to %s:%d' % proxy_writer.get_extra_info('peername'))
		proxy_writer.write(SOCKS5Request.construct(SOCKS5Command.CONNECT, target.get_addr()[0], target.get_addr()[1]).to_bytes())
		t = yield from asyncio.wait_for(proxy_writer.drain(), timeout=1)

		rep = yield from asyncio.wait_for(SOCKS5Reply.from_streamreader(proxy_reader), timeout=self.timeout)
		if rep.REP != SOCKS5ReplyType.SUCCEEDED:
			logging.info('Failed to connect to proxy %s! Server replied: %s' % (proxy_writer.get_extra_info('peername'), repr(rep.REP)))
			raise Exception('Authentication failure!')

		#at this point everything seems to be okay, now let's check if the connect address is the same
		logging.debug('Server reply from %s : %s' % (proxy_writer.get_extra_info('peername'),repr(rep)))

		if rep.BIND_ADDR == ipaddress.IPv6Address('::') or rep.BIND_ADDR == ipaddress.IPv4Address('0.0.0.0'):
			logging.debug('Same socket can be used now on %s:%d' % (proxy_writer.get_extra_info('peername')))
			#this means that the communication can continue on the same socket!
			logging.info('Proxy connection succeeded')
			return proxy_reader, proxy_writer

		else:
			reader, writer = yield from asyncio.wait_for(
				asyncio.open_connection(host=str(rep.BIND_ADDR), port=rep.BIND_PORT),
				timeout=10)
			logging.info('Proxy connection succeeded')
			return reader, writer

	@asyncio.coroutine
	def get_multitunnel(self, servers, target, recursion = 0, proxy_reader = None, proxy_writer = None):
		"""
		should return a socket or throw exception
		"""
		if proxy_reader is None:
			proxy_reader, proxy_writer = yield from asyncio.wait_for(self.connect_proxy(servers[recursion]), timeout=10)

		if recursion < (len(servers) - 1):
			taddr = proxy_writer.get_extra_info('peername')
			proxy_reader, proxy_writer = yield from asyncio.wait_for(self.create_tunnel(servers[recursion+1], servers[recursion], proxy_reader, proxy_writer), timeout = 10)
			if proxy_writer.get_extra_info('peername') != taddr:
				# here the server opens a different socet for us, but following this would require
				# an algo that is too complex for me
				raise Exception('Socks5 server at %s:%d opened a different tunneling socket than the one we connected to! This feature is not supported yet! You may want to remove this server from your list' % taddr)
			else:
				proxy_reader, proxy_writer = yield from asyncio.wait_for(
					self.get_multitunnel(
						servers, target, recursion = recursion+1, proxy_reader = proxy_reader, proxy_writer = proxy_writer
					),
					timeout = 10
				)
				return proxy_reader, proxy_writer
		
		else:
			taddr = proxy_writer.get_extra_info('peername')
			proxy_reader, proxy_writer = yield from asyncio.wait_for(self.create_tunnel(target, servers[recursion], proxy_reader, proxy_writer), timeout = 10)
			if proxy_writer.get_extra_info('peername') != taddr:
				raise Exception('Socks5 server at %s:%d opened a different tunneling socket than the one we connected to! This feature is not supported yet! You may want to remove this server from your list' % taddr)

			return proxy_reader, proxy_writer

	@asyncio.coroutine
	def proxyfy(self, client_reader, client_writer):
		stop_event = asyncio.Event()
		target = SOCKS5ServerConfig.construct(self.remote_addr, self.remote_port)
		if len(self.servers) == 1:
			proxy_reader, proxy_writer = yield from asyncio.wait_for(self.connect_proxy(self.servers[0]), timeout = 10)
			proxy_reader, proxy_writer = yield from asyncio.wait_for(self.create_tunnel(target, self.servers[0], proxy_reader, proxy_writer), timeout = 10)

		else:
			servers = copy.deepcopy(self.servers)
			if self.randomize_servers:
				shuffle(servers)
			logging.info(servers)
			proxy_reader, proxy_writer = yield from asyncio.wait_for(self.get_multitunnel(servers, target), timeout = 10)

		task = asyncio.Task(self.proxy_forwarder(proxy_reader, client_writer, proxy_writer.get_extra_info('peername'), stop_event))
		task = asyncio.Task(self.proxy_forwarder(client_reader, proxy_writer, client_writer.get_extra_info('peername'), stop_event))

		logging.info('Tunnel is ready!')
		t = yield from asyncio.wait_for(stop_event.wait(), timeout = None)
		return

	def handle_client(self, client_reader, client_writer):
		logging.info('Client connected from %s:%d' % client_writer.get_extra_info('peername'))
		task = asyncio.Task(self.proxyfy(client_reader, client_writer))
		self.clients[task] = (client_reader, client_writer)

		def client_done(task):
			del self.clients[task]
			client_writer.close()
			logging.info('Client %s:%d disconnected!' % client_writer.get_extra_info('peername'))

		task.add_done_callback(client_done)
		return
		
	def run(self):
		try:
			self.create_listener_socket_config()
			self.server_coro = asyncio.start_server(self.handle_client, sock=self.listener_socket_config)
			logging.info('Server started!')
			self.loop.run_until_complete(self.server_coro)
			self.loop.run_forever()

		except KeyboardInterrupt:
			sys.exit(0)

		except Exception as e:
			traceback.print_exc()
			print(str(e))


def main():
	import argparse
	parser = argparse.ArgumentParser(description = 'SOCKS5 client. Listens on a local TCP port and tunnels the\
	 												connection to the requested destintation',
									 epilog      = 'list of available interfaces:\r\n' + str(interfaces),
									 formatter_class = argparse.RawTextHelpFormatter)
	parser.add_argument("target_address", help="remote IP/domain")
	parser.add_argument("target_port", type=int, help="remote port")
	parser.add_argument("listen_port", nargs='?', type=int, default=5555, help="local port to listen on")
	parser.add_argument("listen_addr", nargs='?', default='127.0.0.1', help="ip to listen on")
	parser.add_argument("-s", "--server", action='append', default=[], help="SOCKS5 server URL.\r\nFormat: socks5://<user>:<pass>@ip:port")
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('-r', '--randomize', action='store_true', help = 'randomize servers to create tunnel (only used if multiple servers configured)')
	parser.add_argument('-t', '--timeout', type=int, default = 10, help='timeout for connecting to the proxies')

	args = parser.parse_args()

	#'socks5://127.0.0.1:9150'
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	if args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		#supplying -vv or -v -v will show the actual data being passed trough the proxy!
		logging.basicConfig(level=1)

	servers = []

	for url in args.server:
		server_config = SOCKS5ServerConfig.from_url(url)
		servers.append(server_config)

	server_props = ServerProperties.from_address(args.listen_addr, args.listen_port)

	cli = Socks5Client()

	cli.server_props = server_props
	try:
		cli.remote_addr = ipaddress.ip_address(args.target_address)
	except:
		#could be domain name
		cli.remote_addr = args.target_address
	
	cli.remote_port = args.target_port
	cli.servers = servers
	cli.randomize_servers = args.randomize
	cli.timeout = args.timeout

	cli.run()


if __name__ == '__main__':
	main()
