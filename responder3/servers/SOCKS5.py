import traceback
import logging
import io
import os
import re
import copy
import time
import asyncio
import socket
import threading
from ipaddress import IPv4Address, IPv6Address
from responder3.utils import ServerFunctionality
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP, ProtocolSession
from responder3.protocols.Socks5 import *

class SOCKS5Session(ProtocolSession):
	def __init__(self, server):
		ProtocolSession.__init__(self, server)
		### Settings controlled
		self.supportedAuthTypes = [SOCKS5Method.PLAIN]
		self.creds = {'admin':'admin'}
		self.proxyMode = SOCKS5ServerMode.NORMAL
		self.proxyTable = None #{ 'ALL:ALL' : 'fake_ip:fake_port'}
		###
		self.allinterface   = IPv4Address('0.0.0.0') #TODO: change this tp '::'if IPv6 is used
		self.cmdParser      = SOCKS5CommandParser()
		self.currentState   = SOCKS5ServerState.NEGOTIATION
		self.mutualAuthType = None
		self.authHandler    = None
		self.remote_reader  = None
		self.remote_writer  = None
		self.proxy_soc      = None
		self.proxy_thread   = None
		self.proxy_control  = None

"""
proxyTable = {
	re.compile('alma.com'): [
		{
			range(1,500) : '127.0.0.1'
		}
	]
}
"""

class SOCKS5Protocol(ResponderProtocolTCP):
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)
		self._buffer_maxsize = 1024*1024
		self._session = copy.deepcopy(server.protocolSession)

	def _connection_lost(self, exc):
		if self._session.proxy_control is not None:
			self._session.proxy_control.set()

	def _parsebuff(self):
		if self._session.currentState != SOCKS5ServerState.RELAYING:
			buff = io.BytesIO(self._buffer)
			cmd = self._session.cmdParser.parse(buff, self._session)
			#after parsing it we send it for processing to the handle
			self._server.handle(cmd, self._transport, self._session)

			self._buffer = buff.read()
			
			if self._buffer != b'':
				self._parsebuff()

		else:
			#self._session.remote_writer.write(self._buffer)
			self._session.proxy_soc.sendall(self._buffer)
			self._buffer = b''

def proxy(soc, transport, control):
	while not control.is_set():
		try:
			data = soc.recv(8192)
			if data == '':
				return
			transport.write(data)
		except Exception as e:
			print(e)
			return


class SOCKS5(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)

	def setup(self):
		self.protocol = SOCKS5Protocol
		self.protocolSession = SOCKS5Session(self.rdnsd)

		self.protocolSession.creds = None
		if 'creds' in self.settings:
			self.protocolSession.creds = self.settings['creds']

		self.protocolSession.supportedAuthTypes = [SOCKS5Method.PLAIN]
		if 'authType' in self.settings:
			self.protocolSession.supportedAuthTypes = []
			at = self.settings['authType']
			if not isinstance(self.settings['authType'], list):
				at = [self.settings['authType']]
			for textAuthType in at:
				self.protocolSession.supportedAuthTypes.append(SOCKS5Method[textAuthType.upper()])


		self.protocolSession.proxyMode = SOCKS5ServerMode.OFF
		if 'proxyMode' in self.settings:
			self.protocolSession.proxyMode = SOCKS5ServerMode[self.settings['proxyMode'].upper()]
		
		if self.protocolSession.proxyMode == SOCKS5ServerMode.EVIL:
			if 'proxyTable' not in self.settings:
				raise Exception('EVIL mode requires proxyTable to be specified!')

			#ughh...
			self.protocolSession.proxyTable = {}
			for ip in self.settings['proxyTable']:
				iprex = ip #cannot deepcopy a regexp apparently... re.compile(ip)
				self.protocolSession.proxyTable[iprex] = []
				for portrangel in self.settings['proxyTable'][ip]:
					for portranged in portrangel:
						print(portranged)
						if portranged.find('-') != -1:
							start, stop = portranged.split('-')
							prange = range(int(start),int(stop))
						else:
							prange = range(int(portranged),int(portranged)+1)

						if portrangel[portranged].find(':') != -1:
							#additional parsing to enable IPv6 addresses...
							marker = portrangel[portranged].rfind(':')
							self.protocolSession.proxyTable[iprex].append({prange : (portrangel[portranged][:marker], int(portrangel[portranged][marker+1:]))})
						else:
							raise Exception('The target address MUST be supplied in IP:PORT format! Problem: %s' % portrangel[portranged])
			print(self.protocolSession.proxyTable)

	def modulename(self):
		return 'SOCKS5'

	"""
	@asyncio.coroutine
	def proxy_open_connection(self, dest_addr, dest_port, transport, session):
		try:
			fut = asyncio.open_connection(dest_addr, dest_port)
			self.remote_reader, self.remote_writer = yield from asyncio.wait_for(fut, timeout=3)
		except asyncio.TimeoutError:
			transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.HOST_UNREACHABLE, IPv4Address('0.0.0.0'), 0).toBytes())
			transport.close()
			return
		except ConnectionRefusedError:
			transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.CONN_REFUSED, IPv4Address('0.0.0.0'), 0).toBytes())
			transport.close()
			return
		except Exception as e:
			print(str(e))
			transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.FAILURE, IPv4Address('0.0.0.0'), 0).toBytes())
			transport.close()
			return

		session.currentState = SOCKS5ServerState.RELAYING
		transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED, IPv4Address('0.0.0.0'), 0).toBytes())

	@asyncio.coroutine
	def proxy_reader(self, transport, session):
		while True:
			try:
				data = yield from session.remote_reader.read(1024)
				transport.write(data)
			except Exception as e:
				print(str(e))
				transport.close()
				return
	"""

	def fake_dest_lookup(self, dest_ip, dest_port, session):
		for ipregx in session.proxyTable:
			#currently no regex cause python doest like to copy them...
			#if ipregx.match(dest_ip):
			if ipregx == dest_ip:
				for portranged in session.proxyTable[ipregx]:
					for portrange in portranged:
						if dest_port in portrange:
							return portranged[portrange]
		#at this point nothing mached
		if '.*' in session.proxyTable:
			for portranged in session.proxyTable['.*']:
				for portrange in portranged:
					if dest_port in portrange:
						return portranged[portrange]

		return None, None

	def start_proxy(self, dest_ip, dest_port, transport, session):
		
		#asyncio.Task(self.proxy_open_connection(str(packet.DST_ADDR), packet.DST_PORT, transport, session))
		#asyncio.Task(self.proxy_reader(transport, session))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.connect((dest_ip, dest_port))
		except ConnectionRefusedError:
			transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.CONN_REFUSED, self.allinterface, 0).toBytes())
			transport.close((dest_ip, dest_port))
			return
		except Exception as e:
			print(str(e))
			transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.FAILURE, self.allinterface, 0).toBytes())
			transport.close()
			return

		session.proxy_soc = s

		session.currentState = SOCKS5ServerState.RELAYING
		transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED, self.allinterface, 0).toBytes())

		session.proxy_control = threading.Event()
		session.proxy_thread = threading.Thread(target=proxy, args=(s,transport, session.proxy_control))
		session.proxy_thread.start()
		self.log(logging.INFO,'Started proxying to %s:%d' % (dest_ip, dest_port), session)

		return

	def handle(self, packet, transport, session):
		try:
			if 'R3DEEPDEBUG' in os.environ:
				self.log(logging.INFO,'Session state: %s Command: %s' % (session.currentState.name, type(packet) if packet is not None else 'NONE'), session)
			#should be checking which commands are allowed in this state...
			if session.currentState == SOCKS5ServerState.NEGOTIATION:
				mutual = list(set(session.supportedAuthTypes).intersection(set(packet.METHODS)))
				if len(mutual) == 0:
					self.log(logging.INFO,'No common authentication types! Client supports %s' % (','.join([str(x) for x in packet.METHODS])), session)
					transport.write(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOTACCEPTABLE).toBytes())
					transport.close()

				print(mutual)
				#selecting preferred auth type
				for authType in session.supportedAuthTypes:
					print(mutual)
					if session.mutualAuthType is not None:
						break
					
					for clientAuthType in mutual:
						if authType == clientAuthType:
							session.mutualAuthType = authType
							session.authHandler = SOCKS5AuthHandler(session.mutualAuthType, session.creds)
							break

				print(session.mutualAuthType)
				if session.mutualAuthType == SOCKS5Method.NOAUTH:
					session.currentState = SOCKS5ServerState.REQUEST #if no authentication is requred then we skip the auth part
				else:
					session.currentState = SOCKS5ServerState.NOT_AUTHENTICATED

				transport.write(SOCKS5NegoReply.construct(session.mutualAuthType).toBytes())

			elif session.currentState == SOCKS5ServerState.NOT_AUTHENTICATED:
				if session.mutualAuthType == SOCKS5Method.PLAIN:
					status, creds = session.authHandler.do_AUTH(packet)
					if status:
						session.currentState = SOCKS5ServerState.REQUEST
						transport.write(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOAUTH).toBytes())
					else:
						transport.write(SOCKS5NegoReply.construct_auth(SOCKS5Method.NOTACCEPTABLE).toBytes())
						transport.close()
				else:
					#put GSSAPI implementation here
					transport.close()
					raise Exception('Not implemented!')

				self.logResult(session, creds.toResult())



			elif session.currentState == SOCKS5ServerState.REQUEST:
				self.log(logging.INFO, 'Remote client wants to connect to %s:%d' % (str(packet.DST_ADDR), packet.DST_PORT), session)
				if packet.CMD == SOCKS5Command.CONNECT:
					if session.proxyMode == SOCKS5ServerMode.OFF:
						#so long and thanks for all the fish...
						transport.close() 
					elif session.proxyMode == SOCKS5ServerMode.NORMAL:
						#in this case the server acts as a normal socks5 server
						#t = threading.Thread(target=self.start_proxy, args=(str(packet.DST_ADDR), packet.DST_PORT, transport, session))
						#t.start()
						self.start_proxy(str(packet.DST_ADDR), packet.DST_PORT, transport, session)
					else:
						#in this case we route the traffic to a specific server :)
						fake_dest_ip, fake_dest_port = self.fake_dest_lookup(str(packet.DST_ADDR), packet.DST_PORT, session)
						if fake_dest_ip is None:
							self.log( logging.INFO,'Could not find fake address for %s:%d' % (str(packet.DST_ADDR), packet.DST_PORT), session)
							transport.close()

						else:
							#t = threading.Thread(target=self.start_proxy, args=(fake_dest_ip, fake_dest_port, transport, session))
							#t.start()
							self.start_proxy(fake_dest_ip, fake_dest_port, transport, session)

				else:
					transport.write(SOCKS5Reply.construct(SOCKS5ReplyType.COMMAND_NOT_SUPPORTED, self.allinterface, 0).toBytes())
					transport.close()



		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),), session)
			pass

