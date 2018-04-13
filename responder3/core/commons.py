#!/usr/bin/env python
import os
import sys
import ssl
import queue
import base64
import enum
import json
import atexit
import datetime
import socket
import platform
import traceback
import ipaddress
import asyncio

from responder3.crypto.hashing import *


class SSLContextBuilder:
	"""
	Object to parse the user-supplied setting and create an ssl.SSLContext class
	"""
	def __init__(self):
		pass

	@staticmethod
	def from_dict(sslsettings, server_side=False):
		"""
		Creates SSL context from dictionary-based configuration
		:param sslsettings: configuration dictionary
		:param server_side: decides that the context will be created as a server or client
		:return: ssl.SSLContext
		"""
		protocols = [ssl.PROTOCOL_SSLv23]
		options = []
		verify_mode = ssl.CERT_NONE
		ciphers = 'ALL'

		if 'protocols' in sslsettings:
			protocols = []
			if isinstance(sslsettings['protocols'], list):
				for proto in sslsettings['protocols']:
					protocols.append(getattr(ssl, proto, 0))
			else:
				protocols.append(getattr(ssl, sslsettings['protocols'], 0))

		if 'options' in sslsettings:
			options = []
			if isinstance(sslsettings['options'], list):
				for option in sslsettings['options']:
					options.append(getattr(ssl, proto, 0))
			else:
				options.append(getattr(ssl, sslsettings['options'], 0))

		if 'verify_mode' in sslsettings:
			verify_mode = getattr(ssl, sslsettings['verify_mode'], 0)

		if 'ciphers' in sslsettings:
			ciphers = sslsettings['ciphers']

		if server_side is None:
			if 'server_side' in sslsettings:
				server_side = sslsettings['server_side']

		context = ssl.SSLContext(protocols[0])
		context.verify_mode = verify_mode
		if server_side or 'certfile' in sslsettings: #server_side>you need certs, if you are a client, you might need certs
			context.load_cert_chain(certfile=sslsettings['certfile'], 
									keyfile=sslsettings['keyfile'])

		context.protocol = 0
		context.options = 0
		for p in protocols:
			context.protocol |= p
		for o in options:
			context.options |= o
		context.set_ciphers(ciphers)
		return context 


class LogEntry:
	"""
	Communications object that is used to pass log information to the LogProcessor
	"""
	def __init__(self, level, name, msg):
		"""

		:param level: log level
		:type level: int
		:param name: name of the module emitting the message
		:type name: str
		:param msg: the message which will be logged
		:type msg: str
		"""
		self.level = level
		self.name  = name
		self.msg   = msg

	def __str__(self):
		return "[%s] %s" % (self.name, self.msg)


class ConnectionFactory:
	def __init__(self, rdnsd):
		"""
		Creates Connetion object from the socket input.
		:param rdnsd: shared dictionary to speed up the rdns lookup
		:type rdnsd: dict created via multiprocessing.Manager()
		"""
		self.rdnsd       = rdnsd

	def from_streamwriter(self, writer):
		"""
		Creates Connection object from streamwriter
		:param writer: Streamwriter
		:type writer: asyncio.Streamwriter
		:return: Connection object
		"""
		protocoltype = writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
		con = Connection()
		con.timestamp = datetime.datetime.utcnow()
		if protocoltype == socket.SOCK_STREAM:
			soc = writer.get_extra_info('socket')
			con.local_ip, con.local_port   = soc.getsockname()
			con.remote_ip, con.remote_port = soc.getpeername()
		
		else:
			con.local_ip, con.local_port   = writer._laddr[:2]
			con.remote_ip, con.remote_port = writer._addr[:2]
		
		self.lookup_rdns(con)
		return con
		
	def lookup_rdns(self, con):
		"""
		Resolves the remote host's IP address to a DNS address.
		First checks if the address has already been resolved by looking it up in the shared rdns dictionary
		:param con: The Connection object specifies the connection settings
		:type con: Connection
		:return: Nothing
		"""

		if con.remote_ip in self.rdnsd:
			con.remote_dns = self.rdnsd[con.remote_ip]
		
		else:
			try:
				con.remote_dns = socket.gethostbyaddr(con.remote_ip)[0]
			except Exception as e:
				pass

			self.rdnsd[con.remote_ip] = con.remote_dns


class ProxyDataType(enum.Enum):
	"""
	The type of the data being logged. This is used for re-parsing the communication from the log file
	"""
	BINARY = 0
	HTTP   = 1
	SOCKS5 = 2
	SOCKS4 = 3
	FTP    = 4
	SMTP   = 5


class ProxyData:
	def __init__(self):
		"""
		Describes the intercepted communication data.
		Used to store or to read back the intercepted comms.
		"""
		self.src_addr  = None
		self.dst_addr  = None
		self.proto     = None
		self.isSSL     = None
		self.timestamp = datetime.datetime.utcnow()
		self.data_type = None
		self.data      = None

	def to_dict(self):
		"""
		Converts the object to a dictionary
		:return: dict
		"""
		t = {}
		t['src_addr'] = [str(self.src_addr[0]), int(self.src_addr[1])]
		t['dst_addr'] = [str(self.dst_addr[0]), int(self.dst_addr[1])]
		t['proto'] = self.proto.value
		t['isSSL'] = self.isSSL
		t['timestamp'] = self.timestamp
		t['data_type'] = self.data_type.value
		if self.data_type == ProxyDataType.BINARY:
			t['data'] = self.data.hex()
		else:
			raise Exception('Data type %s not implemented!' % (self.data_type))
		return t

	@staticmethod
	def from_dict(d):
		"""
		Loads the object from a dictionary
		:param d: The dictionary containing all fileds of the object
		:type d: dict
		:return: ProxyData
		"""
		pd = ProxyData()
		pd.src_addr  = (ipaddress.ip_address(d['src_addr'][0]), int(d['src_addr'][1]))
		pd.dst_addr  = (ipaddress.ip_address(d['dst_addr'][0]), int(d['dst_addr'][1]))
		pd.proto     = ServerProtocol(d['proto'])
		pd.isSSL     = bool(d['isSSL'])
		pd.timestamp = isoformat2dt(d['timestamp'])
		pd.data_type = ProxyDataType(d['data_type'])
		
		if pd.data_type == ProxyDataType.BINARY:
			pd.data = bytes.fromhex(d['data'])
		else:
			raise Exception('Data type %s not implemented!' % (pd.data_type))

		return pd

	def to_json(self):
		"""
		Used to serialize the ProxyData object
		:return: str
		"""
		return json.dumps(self.to_dict(), cls=UniversalEncoder)

	@staticmethod
	def from_json(s):
		"""
		Deserializes the ProxyData object
		:param s: JSON formatted string
		:type s: str
		:return: ProxyData
		"""
		return ProxyData.from_dict(json.loads(s))

	def __str__(self):
		if self.data_type == ProxyDataType.BINARY:
			return '[%s] [%s -> %s]\r\n%s' % (self.timestamp.isoformat(),
													'%s:%d' % self.src_addr, '%s:%d' % self.dst_addr,
													hexdump(self.data))
		else:
			raise Exception('Data type %s not implemented!' % (self.data_type))
		

class Connection:
	def __init__(self):
		"""
		Keeps all the connection related information that is used for logging and/or connection purposes
		"""
		self.remote_ip   = None
		self.remote_dns  = None
		self.remote_port = None
		self.local_ip    = None
		self.local_port  = None
		self.timestamp   = None

	def get_remote_print_address(self):
		"""
		Returns the remote peer's address in a printable format
		:return: str
		"""
		return '%s:%d' % (str(self.remote_ip), int(self.remote_port))

	def get_local_print_address(self):
		"""
		Returns the local address in a printable format
		:return: str
		"""
		return '%s:%d' % (str(self.local_ip), int(self.local_port))

	def get_remote_address(self):
		"""
		Returns the remote peer's address in a socket friendly format
		:return: tuple
		"""
		return str(self.remote_ip), int(self.remote_port)

	def get_local_address(self):
		"""
		Returns the local address in a socket friendly format
		:return: tuple
		"""
		return str(self.local_ip), int(self.local_port)

	def to_dict(self):
		"""
		Converts the object to a dict
		:return: dict
		"""
		t = {}
		t['remote_ip']   = self.remote_ip
		t['remote_port'] = self.remote_port
		t['remote_dns']  = self.remote_dns
		t['local_ip']    = self.local_ip
		t['local_port']  = self.local_port
		t['timestamp']   = self.timestamp
		return t

	def __repr__(self):
		return str(self)

	def __str__(self):
		if self.remote_dns is not None:
			return '[%s] %s:%d -> %s' % (self.timestamp.isoformat(), self.remote_dns, self.remote_port, self.get_local_print_address())
		else:
			return '[%s] %s-> %s' % (self.timestamp.isoformat(), self.get_remote_print_address(), self.get_local_print_address())


class Credential:
	def __init__(self, credtype, domain = None, username = None, password = None, fullhash = None):
		"""
		Credential object is used to log captured credential.
		This is the container for all captured credential info
		:param credtype: The type of the credential
		:type credtype: str
		:param domain: Domain info
		:param username: Username
		:type username: str
		:param password: Password
		:type password: str
		:param fullhash: The full captured credential in any format that is supported by major password crackers
		:type fullhash: str
		"""
		self.credtype = credtype
		self.domain   = domain
		self.username = username
		self.password = password
		self.fullhash     = fullhash
		self.module   = None
		self.client_addr  = None
		self.client_rdns  = None
		self.fingerprint = None

	def to_dict(self):
		"""
		Converts the object to a dict
		:return: dict
		"""
		t = {}
		t['type'] = self.credtype
		t['domain'] = self.domain
		t['username'] = self.username
		t['password'] = self.password
		t['fullhash'] = self.fullhash
		t['module'] = self.module
		t['client_addr'] = self.client_addr
		t['client_rdns'] = self.client_rdns
		return t

	def __str__(self):
		return '%s %s %s' % (self.type, self.domain, self.fullhash)


class PoisonResult:
	def __init__(self):
		"""
		Container for messages captured or emitted by poisoner modules
		"""
		self.module = None
		self.target = None
		self.request_name = None
		self.request_type = None
		self.poison_name = None
		self.poison_addr = None
		self.mode = None

	def __repr__(self):
		return str(self)

	def __str__(self):
		if self.mode == PoisonerMode.ANALYSE:
			return '[%s] Recieved request from IP: %s to resolve: %s' % (self.module, self.target, self.request_name)
		else:
			return '[%s] Spoofing target: %s for the request: %s which matched the expression %s. Spoof address %s' % (self.module, self.target, self.request_name, self.poison_name, self.poison_addr)


class EmailEntry:
	def __init__(self):
		"""
		Container for emails captured
		"""
		self.fromAddress = None #string
		self.toAddress   = None #list
		self.email       = None #email object (from the email package)


class UniversalEncoder(json.JSONEncoder):
	"""
	Used to override the default json encoder to provide a direct serialization for formats
	that the default json encoder is incapable to serialize
	"""
	def default(self, obj):
		if isinstance(obj, datetime.datetime):
			return obj.isoformat()
		elif isinstance(obj, enum.Enum):
			return obj.value
		else:
			return json.JSONEncoder.default(self, obj)


def timestamp2datetime(dt):
	"""
	Converting Windows timestamps to datetime.datetime format
	:param dt: Windows timestamp as array of bytes
	:type dt: bytearray
	:return: datetime.datetime
	"""
	us = int.from_bytes(dt, byteorder='little')/ 10.
	return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=us)


class PoisonerMode(enum.Enum):
	"""
	Enum to specify the posioner module's mode of operation
	"""
	SPOOF = enum.auto()
	ANALYSE = enum.auto()


class ServerFunctionality(enum.Enum):
	"""
	Enum to specify the server's mode of operation
	"""
	HONEYPOT = 0
	SERVER   = 1
	TARPIT   = 2


# values MUST be lists!
defaultports = {
	"DNS"  : [(53, 'udp'),(53, 'tcp')],
	"DHCP" : [(67, 'udp')],
	"NTP"  : [(123, 'udp')],
	"HTTP" : [(80, 'tcp')],
	"HTTPS": [(443, 'tcp')],
	"FTP"  : [(21, 'tcp')],
	"SMTP" : [(25, 'tcp')],
	"POP3" : [(110, 'tcp')],
	"POP3S": [(995, 'tcp')],
	"IMAP" : [(143, 'tcp')],
	"IMAPS": [(993, 'tcp')],
	"SMB"  : [(445, 'tcp')],
	"NBTNS": [(137, 'udp')],
	"SOCKS5":[(1080, 'tcp')],
	"LLMNR": [(5355, 'udp')],
	"MDNS" : [(5353, 'udp')],
	"HTTPProxy":[(8080, 'tcp')],
}


def byealex(name_of_pid):
	pidfile = str(name_of_pid)
	os.remove(pidfile)


def handle_systemd(pidfile):
	if os.path.isfile(pidfile):
		print ("%s already exists, exiting" % pidfile)
		sys.exit()

	pid = str(os.getpid())
	with open(pidfile, 'w') as f:
		f.write(pid)
	
	atexit.register(byealex,pidfile)


class ResponderPlatform(enum.Enum):
	"""
	Enum to specify the platform the code is running on
	"""
	UNKNOWN = 0
	WINDOWS = 1
	LINUX   = 2
	MAC     = 3


def get_platform():
	"""
	Detects the current platform
	:return: ResponderPlatform
	"""
	p = platform.system()
	if p == 'Linux':
		return ResponderPlatform.LINUX
	elif p == 'Windows':
		return ResponderPlatform.WINDOWS
	elif p == 'Darwin':
		return ResponderPlatform.MAC
	else:
		return ResponderPlatform.UNKNOWN


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
					sock.setsockopt(socket.SOL_SOCKET, 25, socket_config.bind_iface.encode())
					sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
				sock.setblocking(False)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				# print(str(bind_ip_override) if bind_ip_override is not None else str(socket_config.bind_addr))
				# print(int(socket_config.bind_port))
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
					sock.setsockopt(socket.SOL_SOCKET, 25, socket_config.bind_iface.encode())
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
					sock.setsockopt(socket.SOL_SOCKET, 25, socket_config.bind_iface.encode())
					sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,1)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)		
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
					sock.setsockopt(socket.SOL_SOCKET, 25, socket_config.bind_iface.encode())
					sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,1)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
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
		
		return sock
	except Exception as e:
		#print(socket_config)
		raise type(e)(str(e) +
				'Failed to set up socket for on IP %s PORT %s FAMILY %s IP_OVERRIDE %s' % (
					str(socket_config.bind_addr),
					socket_config.bind_port,
					socket_config.bind_family,
					str(bind_ip_override)),
					sys.exc_info()[2]).with_traceback(sys.exc_info()[2])


class ConnectionClosed(Exception):
	pass


@asyncio.coroutine
def read_or_exc(reader, n, timeout = None):
	"""
	Helper function to read N amount of data from the wire.
	:param reader: The reader object
	:type reader: asyncio.StreamReader
	:param n: The maximum amount of bytes to read. BEWARE: this will not read exactly that amount of data!
	:type n: int
	:param timeout: Time in seconds to wait for the reader to return data
	:type timeout: int
	:return: bytearray
	"""
	try:
		data = yield from asyncio.wait_for(reader.read(n), timeout = timeout)
	except:
		raise ConnectionClosed()

	if data == b'':
		if reader.at_eof():
			raise ConnectionClosed()

	return data


@asyncio.coroutine
def readuntil_or_exc(reader, pattern, timeout = None):
	"""
	Helper function to read the wire until a certain pattern is reached.
	:param reader: The reader object
	:type reader: asyncio.StreamReader
	:param pattern: The pattern marking the end of read
	:type pattern: bytearray
	:param timeout: Time in seconds to wait for the reader to reach the pattern
	:type timeout: int
	:return: bytearray
	"""
	try:
		data = yield from asyncio.wait_for(reader.readuntil(pattern), timeout = timeout)
	except:
		raise ConnectionClosed()

	if data == b'':
		if reader.at_eof():
			raise ConnectionClosed()

	return data


@asyncio.coroutine
def readline_or_exc(reader, timeout = None):
	"""
	Helper function to read the wire until an end-of-line character is reached.
	:param reader: The reader object
	:type reader: asyncio.StreamReader
	:param timeout: Time in seconds to wait for the reader to reach the pattern
	:type timeout: int
	:return: bytearray
	"""
	try:
		data = yield from asyncio.wait_for(reader.readline(), timeout = timeout)
	except:
		raise ConnectionClosed()

	if data == b'':
		if reader.at_eof():
			raise ConnectionClosed()

	return data


@asyncio.coroutine
def sendall(writer, data):
	"""
	Helper function that writes all the data to the wire
	:param writer: Writer object
	:type writer: asyncio.StreamWriter
	:param data: Data to be written
	:type data: bytearray
	:return: None
	"""
	try:
		writer.write(data)
		yield from writer.drain()
	except Exception as e:
		raise ConnectionClosed()


# thank you Python developers who after A FUCKING DECADE
# could not figure out a way to make your datetime.datetime
# object in a format that is reversible
# now it's either this bullshit "solution" OR installing a 3rd party
# lib that have to GUESS YOUR SHITTY FORMAT
# PS: "isoformat" doesn't even conforming to the ISO standard..
def isoformat2dt(isostr):
	"""
	Converts back the string result of datetime.datateime.isoformat() to a datetime.datetime object
	:param isostr: string output of datetime.datetime.isoformat()
	:type isostr: str
	:return: datetime.datetime
	"""
	dt, _, us = isostr.partition(".")
	dt = datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
	us = int(us.rstrip("Z"), 10)
	return dt + datetime.timedelta(microseconds=us)


# https://gist.github.com/ImmortalPC/c340564823f283fe530b
def hexdump(src, length=16, sep='.'):
	"""
	Pretty printing binary data blobs
	:param src: Binary blob
	:type src: bytearray
	:param length: Size of data in each row
	:type length: int
	:param sep: Character to print when data byte is non-printable ASCII
	:type sep: str(char)
	:return: str
	"""
	result = []

	for i in range(0, len(src), length):
		subSrc = src[i:i+length]
		hexa = ''
		isMiddle = False
		for h in range(0,len(subSrc)):
			if h == length/2:
				hexa += ' '
			h = subSrc[h]
			if not isinstance(h, int):
				h = ord(h)
			h = hex(h).replace('0x', '')
			if len(h) == 1:
				h = '0'+h
			hexa += h+' '
		hexa = hexa.strip(' ')
		text = ''
		for c in subSrc:
			if not isinstance(c, int):
				c = ord(c)
			if 0x20 <= c < 0x7F:
				text += chr(c)
			else:
				text += sep
		result.append(('%08X:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i, hexa, text))

	return '\n'.join(result)


def get_mutual_preference(preference, offered):
	# this is a commonly used algo when we need to determine the mutual option
	# which is both supported by the client and the server, in order of the
	# server's preference
	"""
	Generic function to determine which option to use from two lists of options offered by two parties.
	Returns the option that is mutual and in the highes priority of the preference
	:param preference: A list of options where the preference is set by the option's position in the list (lower is most preferred)
	:type preference: list
	:param offered: A list of options that the other party can offer
	:type offered: list
	:return: tuple
	"""
	clinet_supp = set(offered)
	server_supp = set(preference)
	common_supp = server_supp.intersection(clinet_supp)
	if common_supp is None:
		return None, None
	
	preferred_opt = None
	for srv_option in preference:
		for common_option in common_supp:
			if common_option == srv_option:
				preferred_opt = srv_option
				break
		else:
			continue
		break
	
	# getting index of the preferred option...
	preferred_opt_idx = 0
	for option in offered:
		if option == preferred_opt:
			# preferred_dialect_idx += 1
			break
		preferred_opt_idx += 1

	return preferred_opt, preferred_opt_idx


def read_element(line, marker = ' ', marker_end = None, toend = False):
	"""
	Helper function to read a substring from a string.
	Returns a tuple containing the substring and the remaining data starting from the end of the substring.
	:param line: the data to read from
	:type line: str
	:param marker: if marker_end is not defined it marks the end of the returned substring
					if marker is defined it marks the beginning of the returned substring
	:type marker: str
	:param marker_end: if defined it marks the end of the returned substring
	:param marker_end: str
	:param toend:
	:type toend: bool
	:return: tuple
	"""
	if marker_end is None:
		m = line.find(marker)
		if m == -1:
			if toend:
				return line, ''
			print(line)
			raise Exception('Marker not found!')
		element = line[:m]
		line = line[m+len(marker):]
		return element, line
	else:
		start = line.find(marker)
		end   = line.find(marker_end)
		if start == -1 or end == -1 or end <= start:
			raise Exception('Marker not found!')
		element = line[start:end]
		line = line[end:]
		return element, line
