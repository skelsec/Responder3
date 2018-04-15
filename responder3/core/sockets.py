import ipaddress
import socket
import sys

from responder3.core.commons import ResponderPlatform, get_platform


class SocketConfig:
	def __init__(self):
		"""
		Holds all necessary information to create a listening socket
		"""

		self.bind_iface  = None
		self.bind_port   = None
		self.bind_family = None
		self.bind_protocol = None
		self.bind_addr = None
		self.bind_iface_idx = None
		self.reuse_address = True
		self.reuse_port = True
		self.is_ssl_wrapped = False
		self.is_server = True
		self.platform = get_platform()

	def get_protocolname(self):
		"""
		Returns protocol type as string
		:return: str
		"""
		if self.bind_protocol == socket.SOCK_STREAM:
			return 'TCP'
		elif self.bind_protocol == socket.SOCK_DGRAM:
			return 'UDP'
		else:
			return 'UNKNOWN'

	def get_address(self):
		"""
		Resturns address as tuple
		:return: tuple
		"""
		return (str(self.bind_addr), self.bind_port)

	def get_print_address(self):
		"""
		Returns address in a printable form
		:return: str
		"""
		return '%s:%d' % (str(self.bind_addr), self.bind_port)

	def get_server_kwargs(self):
		"""
		Returns a dict to be used in asyncio.create_server function
		:return: dict
		"""
		return {
			'host'         : str(self.bind_addr),
			'port'         : self.bind_port,
			'family'       : self.bind_family,
			'reuse_address': self.reuse_address,
			'reuse_port'   : self.reuse_port
		}

	def __repr__(self):
		return str(self)

	def __str__(self):
		t  = '==SocketConfig==\r\n'
		t += 'Interface: %s\r\n' % self.bind_iface
		t += 'Iface idx: %s\r\n' % self.bind_iface_idx
		t += 'Address  : %s\r\n' % str(self.bind_addr)
		t += 'Port     : %s\r\n' % self.bind_port
		t += 'Protocol : %s\r\n' % self.bind_protocol
		t += 'Family   : %s\r\n' % self.bind_family
		return t


def setup_base_socket(socket_config, bind_ip_override = None):
	"""
	This function provides a platform-independent way to create a socket based on the socket configuration
	:param socket_config: Socket configuration object
	:type socket_config: SocketConfig
	:param bind_ip_override: Used to override the bind_addr value of the socket configuration,
							and creates the socket with the overridden value
	:return: socket.socket
	"""
	try:
		sock = None
		if socket_config.bind_protocol == socket.SOCK_DGRAM:
			if socket_config.bind_family == 4:
				sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
				if socket_config.platform == ResponderPlatform.LINUX:
					if socket_config.reuse_address:
						sock.setsockopt(socket.SOL_SOCKET, 25, socket_config.bind_iface.encode())
					if socket_config.reuse_port:
						sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
				sock.setblocking(False)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				sock.bind(
					(
						str(bind_ip_override) if bind_ip_override is not None else str(socket_config.bind_addr),
						int(socket_config.bind_port)
					)
				)

			elif socket_config.bind_family == 6:
				if not socket.has_ipv6:
					raise Exception('IPv6 is NOT supported on this platform')
				if str(bind_ip_override) == '0.0.0.0':
					bind_ip_override = ipaddress.ip_address('::')
				sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
				sock.setblocking(False)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

				if socket_config.platform in [ResponderPlatform.LINUX, ResponderPlatform.MAC]:
					if socket_config.reuse_address:
						sock.setsockopt(socket.SOL_SOCKET, 25, socket_config.bind_iface.encode())
					if socket_config.reuse_port:
						sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

				if socket_config.platform in [ResponderPlatform.LINUX, ResponderPlatform.MAC]:
					sock.bind(
						(
							str(bind_ip_override) if bind_ip_override is not None else str(socket_config.bind_addr),
							int(socket_config.bind_port),
							socket_config.bind_iface_idx
						)
					)
				elif socket_config.platform == ResponderPlatform.WINDOWS:
					sock.bind(
						(
							str(socket_config) if bind_ip_override is not None else str(socket_config.bind_addr),
							int(socket_config.bind_port)
						)
					)

			else:
				raise Exception('Unknown IP version')

		elif socket_config.bind_protocol == socket.SOCK_STREAM:
			if socket_config.bind_family == 4:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
				sock.setblocking(False)
				if socket_config.platform == ResponderPlatform.LINUX:
					if socket_config.reuse_address:
						sock.setsockopt(socket.SOL_SOCKET, 25, socket_config.bind_iface.encode())
					if socket_config.reuse_port:
						sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR ,1)
				sock.bind(
					(
						str(bind_ip_override) if bind_ip_override is not None else str(socket_config.bind_addr),
						int(socket_config.bind_port)
					)
				)

			elif socket_config.bind_family == 6:
				if not socket.has_ipv6:
					raise Exception('IPv6 is NOT supported on this platform')
				if str(bind_ip_override) == '0.0.0.0':
					bind_ip_override = ipaddress.ip_address('::')
				sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
				sock.setblocking(False)
				if socket_config.platform in [ResponderPlatform.LINUX, ResponderPlatform.MAC]:
					if socket_config.reuse_address:
						sock.setsockopt(socket.SOL_SOCKET, 25, socket_config.bind_iface.encode())
					if socket_config.reuse_port:
						sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR ,1)
				if socket_config.platform in [ResponderPlatform.LINUX, ResponderPlatform.MAC]:
					sock.bind(
						(
							str(bind_ip_override) if bind_ip_override is not None else str(socket_config.bind_addr),
							int(socket_config.bind_port),
							socket_config.bind_iface_idx
						)
					)
				elif socket_config.platform == ResponderPlatform.WINDOWS:
					sock.bind(
						(
							str(bind_ip_override) if bind_ip_override is not None else str(socket_config.bind_addr),
							int(socket_config.bind_port)
						)
					)

			else:
				raise Exception('Unknown IP version')
		else:
			raise Exception('Unknown protocol!')

		if not socket_config.is_server:
			socket_config.bind_port = socket.gethostname()[1]

		return sock
	except Exception as e:
		# print(socket_config)
		raise type(e)(str(e) +
					  'Failed to set up socket for on IP %s PORT %s FAMILY %s IP_OVERRIDE %s' % (
						  str(socket_config.bind_addr),
						  socket_config.bind_port,
						  socket_config.bind_family,
						  str(bind_ip_override)),
					  sys.exc_info()[2]).with_traceback(sys.exc_info()[2])
