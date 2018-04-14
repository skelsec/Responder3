import logging
import asyncio

from responder3.core.commons import *
from responder3.protocols.SOCKS5 import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

class SOCKS5Session(ResponderServerSession):
	def __init__(self, *args):
		ResponderServerSession.__init__(self, *args)
		self.current_state   = SOCKS5ServerState.NEGOTIATION
		self.allinterface = ipaddress.ip_address('0.0.0.0')
		self.supported_auth_types = None
		self.mutual_auth_type = None
		self.auth_handler    = None
		self.client_transport= None
		self.proxymode = None
		self.proxytable = None
		self.creds = None
		self.proxy_closed = asyncio.Event()
		self.timeout = None

	def __repr__(self):
		t  = '== SOCKS5Session ==\r\n'
		t += 'current_state:      %s\r\n' % repr(self.current_state)
		t += 'supported_auth_types: %s\r\n' % repr(self.supported_auth_types)
		t += 'mutual_auth_type: %s\r\n' % repr(self.mutual_auth_type)
		t += 'auth_handler: %s\r\n' % repr(self.auth_handler)
		t += 'client_transport: %s\r\n' % repr(self.client_transport)
		t += 'proxymode: %s\r\n' % repr(self.proxymode)
		t += 'proxytable: %s\r\n' % repr(self.proxytable)
		return t


class SOCKS5(ResponderServer):
	def init(self):
		self.parser = SOCKS5CommandParser
		self.parse_settings()
		
	def parse_settings(self):
		self.session.creds = None
		self.session.supported_auth_types = [SOCKS5Method.PLAIN]
		self.session.proxymode = SOCKS5ServerMode.OFF

		if self.settings is not None:
			if 'creds' in self.settings:
				self.session.creds = self.settings['creds']

			if 'authtype' in self.settings:
				self.session.supported_auth_types = []
				at = self.settings['authtype']
				if not isinstance(self.settings['authtype'], list):
					at = [self.settings['authtype']]

				for authtype in at:
					self.session.supported_auth_types.append(SOCKS5Method[authtype.upper()])

			if 'proxymode' in self.settings:
				self.session.proxymode = SOCKS5ServerMode[self.settings['proxymode'].upper()]

			if self.session.proxymode == SOCKS5ServerMode.EVIL:
				if 'proxytable' not in self.settings:
					raise Exception('EVIL mode requires proxyTable to be specified!')

				for entry in self.settings['proxytable']:
					for ip in entry:
						iprex = re.compile(ip)
						self.session.proxytable[iprex] = []
						for portranged in entry[ip]:
							for portrange in portranged:
								if portrange.find('-') != -1:
									start, stop = portrange.split('-')
									prange = range(int(start.strip()),int(stop.strip())+1)
							
								else:
									prange = range(int(portrange),int(portrange)+1)
								
								if portranged[portrange].find(':') != -1:
									# additional parsing to enable IPv6 addresses...
									marker = portranged[portrange].rfind(':')
									self.session.proxytable[iprex].append({prange: (portranged[portrange][:marker], int(portranged[portrange][marker+1:]))})
								else:
									raise Exception('The target address MUST be supplied in IP:PORT format! Problem: %s' % portranged[portrange])

	def fake_dest_lookup(self, dest_ip, dest_port):
		for ipregx in self.session.proxytable:
			if ipregx.match(dest_ip):
				for portranged in self.session.proxytable[ipregx]:
					for portrange in portranged:
						if dest_port in portrange:
							return portranged[portrange]

		return None, None


	@asyncio.coroutine
	def parse_message(self, timeout=None):
		try:
			req = yield from asyncio.wait_for(self.parser.from_streamreader(self.creader, self.session), timeout=timeout)
			return req
		except asyncio.TimeoutError:
			self.log('Timeout!', logging.DEBUG)

	@asyncio.coroutine
	def send_data(self, data):
		self.cwriter.write(data)
		yield from self.cwriter.drain()

	@asyncio.coroutine
	def modify_data(self, data):
		return data

	@asyncio.coroutine
	def generic_read(self, reader):
		return reader.read(1024)

	@asyncio.coroutine
	def proxy_forwarder(self, reader, writer, laddr, raddr):
		while not self.session.proxy_closed.is_set():
			try:
				data = yield from asyncio.wait_for(self.generic_read(reader), timeout=self.session.timeout)
			except asyncio.TimeoutError:
				self.log('Timeout!', logging.DEBUG)
				self.session.proxy_closed.set()
				break	
			
			if data == b'' or reader.at_eof():
				print('Connection closed!')
				self.session.proxy_closed.set()
				break
			

			self.logProxy('original data: %s' % data.hex(), laddr, raddr)
			self.logProxyData(data, laddr, raddr, False, ProxyDataType.BINARY)
			modified_data = yield from self.modify_data(data)
			if modified_data != data:
				self.logProxy('modified data: %s' % repr(modified_data),laddr, raddr)
			
			try:
				writer.write(modified_data)
				yield from asyncio.wait_for(writer.drain(), timeout=self.session.timeout)
			except asyncio.TimeoutError:
				self.log('Timeout!', logging.DEBUG)
				self.session.proxy_closed.set()
				break

		return


	@asyncio.coroutine
	def run(self):
		try:
			while True:
				msg = yield from asyncio.wait_for(self.parse_message(), timeout = 1)
				if self.session.current_state == SOCKS5ServerState.NEGOTIATION:
					mutual, mutual_idx = get_mutual_preference(self.session.supported_auth_types,msg.METHODS)
					if mutual is None:
						self.log('No common authentication types! Client supports %s' % (','.join([str(x) for x in msg.METHODS])))
						t = yield from asyncio.wait_for(self.send_data(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOTACCEPTABLE).to_bytes()), timeout = 1)
						return
					self.log('Mutual authentication type: %s' % mutual, logging.DEBUG)
					self.session.mutual_auth_type = mutual
					self.session.authHandler = SOCKS5AuthHandler(self.session.mutual_auth_type, self.session.creds) 

					if self.session.mutual_auth_type == SOCKS5Method.NOAUTH:
						self.session.current_state = SOCKS5ServerState.REQUEST # if no authentication is requred then we skip the auth part
					else:
						self.session.current_state = SOCKS5ServerState.NOT_AUTHENTICATED

					t = yield from asyncio.wait_for(self.send_data(SOCKS5NegoReply.construct(self.session.mutual_auth_type).to_bytes()), timeout = 1)

				elif self.session.current_state == SOCKS5ServerState.NOT_AUTHENTICATED:
					if self.session.mutual_auth_type == SOCKS5Method.PLAIN:
						status, creds = self.session.authHandler.do_AUTH(msg)
						if status:
							self.session.current_state = SOCKS5ServerState.REQUEST
							t = yield from asyncio.wait_for(self.send_data(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOAUTH).to_bytes()), timeout = 1)
						else:
							t = yield from asyncio.wait_for(self.send_data(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOTACCEPTABLE).to_bytes()), timeout = 1)
							return
					else:
						#put GSSAPI implementation here
						raise Exception('Not implemented!')

				elif self.session.current_state == SOCKS5ServerState.REQUEST:
					self.log('Remote client wants to connect to %s:%d' % (str(msg.DST_ADDR), msg.DST_PORT))
					if msg.CMD == SOCKS5Command.CONNECT:
						if self.session.proxymode == SOCKS5ServerMode.OFF:
							#so long and thanks for all the fish...
							return

						elif self.session.proxymode == SOCKS5ServerMode.NORMAL:
							#in this case the server acts as a normal socks5 server
							proxy_reader, proxy_writer = yield from asyncio.wait_for(asyncio.open_connection(host=str(msg.DST_ADDR),port = msg.DST_PORT), timeout=1)
							self.log('Connected!', logging.DEBUG)
							self.session.current_state = SOCKS5ServerState.RELAYING
							t = yield from asyncio.wait_for(self.send_data(SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED, self.session.allinterface, 0).to_bytes()), timeout = 1)
							self.loop.create_task(self.proxy_forwarder(proxy_reader, self.cwriter, (str(msg.DST_ADDR),int(msg.DST_PORT)), self.caddr))
							self.loop.create_task(self.proxy_forwarder(self.creader, proxy_writer, self.caddr, (str(msg.DST_ADDR),int(msg.DST_PORT))))

							yield from asyncio.wait_for(self.session.proxy_closed.wait(), timeout = None)
							return
						
						else:
							#in this case we route the traffic to a specific server :)
							fake_dest_ip, fake_dest_port = self.fake_dest_lookup(str(msg.DST_ADDR), msg.DST_PORT)
							if fake_dest_ip is None:
								self.log('Could not find fake address for %s:%d' % (str(msg.DST_ADDR), msg.DST_PORT))
								return

							else:
								proxy_reader, proxy_writer = yield from asyncio.wait_for(asyncio.open_connection(host=str(fake_dest_ip),port = fake_dest_port), timeout=1)
								self.log('Connected!', logging.DEBUG)
								self.session.current_state = SOCKS5ServerState.RELAYING
								t = yield from asyncio.wait_for(self.send_data(SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED, self.allinterface, 0).to_bytes()), timeout = 1)
								self.loop.create_task(self.proxy_forwarder(proxy_reader, self.cwriter, (str(fake_dest_ip),int(fake_dest_port)), self.caddr))
								self.loop.create_task(self.proxy_forwarder(self.creader, proxy_writer, self.caddr,  (str(fake_dest_ip),int(fake_dest_port))))

								yield from asyncio.wait_for(self.session.proxy_closed.wait(), timeout = None)
								return

					else:
						t = yield from asyncio.wait_for(SOCKS5Reply.construct(SOCKS5ReplyType.COMMAND_NOT_SUPPORTED, self.session.allinterface, 0).to_bytes(), timeout = 1)
						return				
					
		except Exception as e:
			self.log_exception()
			pass
