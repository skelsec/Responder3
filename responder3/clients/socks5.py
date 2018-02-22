import traceback
import logging
import io
import os
import copy
import time
import asyncio
import socket
import threading
from random import shuffle
from ipaddress import IPv4Address, IPv6Address
from responder3.utils import ServerFunctionality
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP, ProtocolSession
from responder3.protocols.Socks5 import *

class SOCKS5Server():
	def __init__(self):
		self.ip       = ''
		self.port     = ''
		self.timeout  = ''
		self.username = ''
		self.password = ''

	def getAddr(self):
		return (str(self.ip), self.port)

	def constrcut(ip, port, timeout = 1, username = None, password = None):
		self.ip       = ip
		if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
			self.ip       = ipadress.ip_address(ip)
		
		self.port     = int(port)
		self.timeout  = int(timeout)
		self.username = username
		self.password = password

	def from_json(s):
		return SOCKS5Server.from_dict(json.loads(s))

	def from_dict(d):
		s = SOCKS5Server()
		s.ip       = ipaddress.ip_address(d['ip'])
		s.port     = int(d['port'])
		s.timeout  = int(d['timeout'])
		s.username = d['username']
		s.password = d['password']
		return s

class TCPProxyThread():
	def __init__(self):
		self.soc1  = None
		self.soc2 = None
		self.inout_thread = None
		self.outin_thread = None
		self.threads = []

	def construct(soc_in, soc_out):
		tp = TCPProxyThread()
		tp.soc1  = soc_in
		tp.soc2 = soc_out
		return tp


	def proxy(soc1, soc2):
		try:
			while True:
				data = soc1.recv(4096)
				if data == b'':
					break
				soc2.sendall(data)
			print('Socket closed!')
		except Exception as e:
			print('Error while proxying: %s' % str(e))



	def run(self):
		t = threading.Thread(target=TCPProxyThread.proxy, args=(self.soc1, self.soc2))
		self.threads.append(t)
		t2 = threading.Thread(target=TCPProxyThread.proxy, args=(self.soc2, self.soc1))
		self.threads.append(t2)

		for t in self.threads:
			t.start()

		for t in self.threads:
			t.join()

class TunnelTrack():
	def __init__(self, level, addr):
		self.leve = level
		self.addr = addr

class Socks5Client():
	def __init__(self):
		self.servers = None
		self.bind_addr = None
		self.bind_port = None
		self.remote_addr = None
		self.remote_port = None
		self.target = None
		self.randomize_servers = False
		self.cmdparser = SOCKS5SocketParser()
		self.listening_socket = None
		self.connection_threads = []
		self.latest_tunnel = None

	def create_listening_socket(self):
		try:
			self.listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self.listening_socket.bind((str(self.bind_addr), self.bind_port))
			self.listening_socket.listen(500)
		except Exception as e:
			raise e

	def connect_proxy(self, server):
		print('Connecting to proxy %s:%d...' % server.getAddr())
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect(server.getAddr())
		except Exception as e:
			raise Exception('Failed to connect to proxy! Reason: %s' % str(e))

	def get_route(self, s, server):
		authmethods = [SOCKS5Method.NOAUTH]
		if server.username is not None:
			authmethods.append(SOCKS5Method.PLAIN)

		print('Sending nego')
		s.sendall(SOCKS5Nego.construct(authmethods).toBytes())
		rep_nego = SOCKS5NegoReply.from_socket(s)
		print('GOT nego reply')
		if rep_nego.METHOD == SOCKS5Method.NOTACCEPTABLE:
			raise Exception('Failed to connect to proxy! No common authentication type!')

		if rep_nego.METHOD == SOCKS5Method.PLAIN:
			print('Doing plain auth')
			s.sendall(SOCKS5PlainAuth.construct(server.username, server.password).toBytes())
			rep_auth_nego = SOCKS5NegoReply.from_socket(s)
			if rep_auth_nego.METHOD != SOCKS5Method.NOAUTH:
				raise Exception('Failed to connect to proxy! Authentication failed!')

		print('Sending connect req')
		s.sendall(SOCKS5Request.construct(SOCKS5Command.CONNECT, server.getAddr()[0], server.getAddr()[1]).toBytes())
		rep = SOCKS5Reply.from_socket(s)
		if rep.REP != SOCKS5ReplyType.SUCCEEDED:
			raise Exception(print('Failed to connect to proxy! Server replied: %s' % (repr(SOCKS5ReplyType.SUCCEEDED))))
			

		#at this point everything seems to be okay, now let's check if the connect address is the same
		print('Server reply: %s' % repr(rep))

		if rep.BIND_ADDR == IPv6Address('::') or rep.BIND_ADDR == IPv4Address('0.0.0.0'):
			#this means that the communication can continue on the same socket!
			return None

		else:
			return (str(rep.BIND_ADDR), rep.BIND_PORT)

	

	def get_multitunnel(self, servers, target, recursion = 0, rsock = None):
		"""
		should return a socket or throw exception
		"""
		if rsock is None:
			rsock = self.connect_proxy(servers[recursion])

		if recursion < len(servers):
			addr = self.get_route(rsock, servers[recursion+1])
			if addr is not None:
				#here the server opens a different socet for us, but following this would require
				#an algo that is too complex for me (like for each and every recirsion layer we'd need to jump back to the original while keeping track of the latest layer's new address)
				raise Exception('This feature is not implemented')
			else:
				return self.get_multitunnel(servers, target, recursion = recursion+1, rsock = rsock):
		
		else:
			addr = self.get_route(rsock, target)
			if addr is not None:
				#here the server opens a different socet for us, but following this would require
				#an algo that is too complex for me (like for each and every recirsion layer we'd need to jump back to the original while keeping track of the latest layer's new address)
				raise Exception('This feature is not implemented ')
			
			return rsock



	def proxyfy(self, clientsock, addr):
		print('Client connected from %s:%d' % (addr[0],addr[1]))
		rsock = None
		servers = shuffle(copy.deepcopy(self.servers)) if self.randomize_servers else copy.deepcopy(self.servers)
		if len(servers) == 1:
			rsock = self.connect_proxy(servers[0])
			addr = self.get_route(servers[0], (self.remote_addr, self.remote_port))
			if addr is None:
				rsock = self.connect_proxy(addr)

		else:
			servers = shuffle(copy.deepcopy(self.servers)) if self.randomize_servers else copy.deepcopy(self.servers)
			rsock = get_multitunnel(servers)

		if rsock is None:
			print('Error happened!')
		proxy = TCPProxy.construct(clientsock, rsock)
		proxy.run()
		
	def run(self):
		try:
			self.create_listening_socket()
			while True:
				clientsock, addr = self.listening_socket.accept()
				cont = threading.Thread(target=self.proxyfy, args=(clientsock, addr))
				self.connection_threads.append(cont)
				cont.start()
		except Exception as e:
			print(str(e))
			traceback.print_exc()

def main():
	import argparse
	parser = argparse.ArgumentParser(description = 'SOCKS5 client. Listens on a local TCP port and tunnels the connection to the requested destintation')
	parser.add_argument("bind_port", type=int, default = 5555, help="local port to listen on")
	parser.add_argument("bind_address", default = '0.0.0.0', help="ip address to listen on")
	parser.add_argument("remote_address", help="remote IP/domain")
	parser.add_argument("remote_port", type=int, help="remote port")

	args = parser.parse_args()

	s = SOCKS5Server()
	s.ip       = '127.0.0.1'
	s.port     = 9150
	s.timeout  = 2
	s.username = None
	s.password = None

	servers = [s]


	cli = Socks5Client()
	cli.bind_addr = ipaddress.ip_address(args.bind_address)
	cli.bind_port = args.bind_port
	try:
		cli.remote_addr = ipaddress.ip_address(args.remote_address)
	except:
		#could be domain name
		cli.remote_addr = args.remote_address
	
	cli.remote_port = args.remote_port
	cli.servers = servers

	cli.run()

if __name__ == '__main__':
	main()