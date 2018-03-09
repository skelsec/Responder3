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

sslcontexttable = {
	#'SSLv2': ssl.PROTOCOL_SSLv2,
	#'SSLv3': ssl.PROTOCOL_SSLv3,
	'SSLv23': ssl.PROTOCOL_SSLv23,
	'TLS'   : ssl.PROTOCOL_TLS,
	'TLSv1' : ssl.PROTOCOL_TLSv1,
	'TLSv11': ssl.PROTOCOL_TLSv1_1,
	'TLSv12': ssl.PROTOCOL_TLSv1_2,
}

class SSLContextBuilder():
	def __init__(self):
		pass

	def from_dict(sslsettings):
		protocols = [ssl.PROTOCOL_SSLv23]
		options = []
		verify_mode = ssl.CERT_NONE
		ciphers = 'ALL'
		server_side = False
		"""
		protocols or ('PROTOCOL_SSLv3','PROTOCOL_TLSv1',
								  'PROTOCOL_TLSv1_1','PROTOCOL_TLSv1_2')

				options = options or ('OP_CIPHER_SERVER_PREFERENCE','OP_SINGLE_DH_USE',
							  'OP_SINGLE_ECDH_USE','OP_NO_COMPRESSION')
		"""
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
		if 'server_side' in sslsettings:
			server_side = sslsettings['server_side']

		print(protocols)
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

class LogEntry():
	"""
	Communications object that is used to pass log information to the LogProcessor
	"""
	def __init__(self, level, name, msg):
		"""
		level: the log level, needs to be a level specified by the built-in logging module (eg. logging.INFO)
		name : name of the source module
		msg  : message that is to be printed in the logs 
		"""
		self.level = level
		self.name  = name
		self.msg   = msg

	def __str__(self):
		return "[%s] %s" % (self.name, self.msg)


class ConnectionStatus(enum.Enum):
	OPENED = 0
	CLOSED = 1
	STATELESS = 3

class ConnectionFactory():
	"""
	Creates Connetion object from the socket input. 
	in: rdns which is a shared dictionary to speed up the rdns lookup
	"""
	def __init__(self, rdnsd):
		self.rdnsd       = rdnsd

	def from_streamwriter(self, writer, protocoltype):
		con = Connection()
		con.timestamp = datetime.datetime.utcnow()
		if protocoltype == ServerProtocol.TCP:
			soc = writer.get_extra_info('socket')
			con.local_ip, con.local_port   = soc.getsockname()
			con.remote_ip, con.remote_port = soc.getpeername()
		
		else:
			con.local_ip, con.local_port   = writer._laddr[:2]
			con.remote_ip, con.remote_port = writer._addr[:2]
		
		self.lookupRDNS(con)
		return con
		
	def lookupRDNS(self, con):
		"""
		Reolves the remote host's IP address to a DNS address. 
		First checks if the address has already been resolved by looking it up in the shared rdns dictionary
		"""
		#if con.remote_ip in self.rdnsd :
		if con.remote_ip in self.rdnsd:
			con.remote_dns = self.rdnsd[con.remote_ip]
		
		else:
			try:
				con.remote_dns = socket.gethostbyaddr(con.remote_ip)[0]
			except Exception as e:
				pass

			self.rdnsd[con.remote_ip] = con.remote_dns

class ProxyDataType(enum.Enum):
	BINARY = 0
	HTTP   = 1
	SOCKS5 = 2
	SOCKS4 = 3
	FTP    = 4
	SMTP   = 5


class ProxyData():
	def __init__(self):
		self.src_addr  = None
		self.dst_addr  = None
		self.proto     = None
		self.isSSL     = None
		self.timestamp = datetime.datetime.utcnow()
		self.data_type = None
		self.data      = None

	def toDict(self):
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
	
	def fromDict(d):
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

	def toJSON(self):
		return json.dumps(self.toDict(), cls=UniversalEncoder)

	def fromJSON(s):
		return ProxyData.fromDict(json.loads(s))

	def __str__(self):
		if self.data_type == ProxyDataType.BINARY:
			return '[%s] [%s -> %s]\r\n%s' % (self.timestamp.isoformat(), '%s:%d' % self.src_addr, '%s:%d' % self.dst_addr, hexdump(self.data))
		else:
			raise Exception('Data type %s not implemented!' % (self.data_type))
		

class Connection():
	"""
	Keeps all the connection related information that is used for logging and/or connection purposes
	"""
	def __init__(self):
		self.remote_ip   = None
		self.remote_dns  = None
		self.remote_port = None
		self.local_ip    = None
		self.local_port  = None
		self.timestamp   = None


	def getRemoteAddress(self):
		return (str(self.remote_ip), int(self.remote_port))

	def getLocalAddress(self):
		return (str(self.local_ip), int(self.local_port))

	def toDict(self):
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
			return '[%s] %s:%d -> %s:%d' % (self.timestamp.isoformat(), self.remote_dns, self.remote_port, self.local_ip,self.local_port )
		else:
			return '[%s] %s:%d -> %s:%d' % (self.timestamp.isoformat(), self.remote_ip, self.remote_port, self.local_ip,self.local_port )


class Credential():
	def __init__(self, credtype, domain = None, username = None, password = None, fullhash = None):
		self.type     = credtype
		self.domain   = domain
		self.username = username
		self.password = password
		self.fullhash     = fullhash
		self.module   = None
		self.client_addr  = None
		self.client_rdns  = None
		self.fingerprint = None

	def toDict(self):
		t = {}
		t['type'] = self.type
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

class PoisonResult():
	def __init__(self):
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

class EmailEntry():
	"""
	If the SMTP server recieved an email it's sent to the log queue for processing
	"""
	def __init__(self):
		self.fromAddress = None #string
		self.toAddress   = None #list
		self.email       = None #email object (from the email package)

class UniversalEncoder(json.JSONEncoder):
	def default(self, obj):
		if isinstance(obj, datetime.datetime):
			return obj.isoformat()
		elif isinstance(obj, enum.Enum):
			return obj.value
		else:
			return json.JSONEncoder.default(self, obj)

def timestamp2datetime(dt):
	us = int.from_bytes(dt, byteorder='little')/ 10.
	return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=us)

class PoisonerMode(enum.Enum):
	SPOOF = enum.auto()
	ANALYSE = enum.auto()

class ServerFunctionality(enum.Enum):
	HONEYPOT = 0
	SERVER   = 1
	TARPIT   = 2
	
class ServerProtocol(enum.Enum):
	TCP = 0
	UDP = 1
	SSL = 2

#values MUST be lists!
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
	"SOCKS5":[(1050, 'tcp')],
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
	UNKNOWN = 0
	WINDOWS = 1
	LINUX   = 2
	MAC     = 3

def get_platform():
	p = platform.system()
	if p == 'Linux':
		return ResponderPlatform.LINUX
	elif p == 'Windows':
		return ResponderPlatform.WINDOWS
	elif p == 'Darwin':
		return ResponderPlatform.MAC
	else:
		return ResponderPlatform.UNKNOWN

def setup_base_socket(server_properties, bind_ip_override = None):
	try:
		sock = None
		if server_properties.bind_porotcol == ServerProtocol.UDP:
			if server_properties.bind_family == socket.AF_INET:
				sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
				if server_properties.platform == ResponderPlatform.LINUX:
					sock.setsockopt(socket.SOL_SOCKET, 25, server_properties.bind_iface.encode())
					sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,1)
				sock.setblocking(False)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)		
				sock.bind(
					(
						str(bind_ip_override) if bind_ip_override is not None else str(server_properties.bind_addr), 
						int(server_properties.bind_port)
					)
				)
				
			elif server_properties.bind_family == socket.AF_INET6:
				if not socket.has_ipv6:
					raise Exception('IPv6 is NOT supported on this platform')
				if str(bind_ip_override) == '0.0.0.0':
					bind_ip_override = ipaddress.ip_address('::')
				sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
				sock.setblocking(False)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
				
				if server_properties.platform in [ResponderPlatform.LINUX, ResponderPlatform.MAC]:
					sock.setsockopt(socket.SOL_SOCKET, 25, server_properties.bind_iface.encode())
					sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,1)
						
				if server_properties.platform in [ResponderPlatform.LINUX, ResponderPlatform.MAC]:
					sock.bind(
						(
							str(bind_ip_override) if bind_ip_override is not None else str(server_properties.bind_addr), 
							int(server_properties.bind_port),
							server_properties.bind_iface_idx
						)
					)
				elif server_properties.platform == ResponderPlatform.WINDOWS:
					sock.bind(
						(
							str(bind_ip_override) if bind_ip_override is not None else str(server_properties.bind_addr), 
							int(server_properties.bind_port)
						)
					)

			else:
				raise Exception('Unknown IP version')

		elif server_properties.bind_porotcol == ServerProtocol.TCP:
			if server_properties.bind_family == socket.AF_INET:
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
				sock.setblocking(False)
				if server_properties.platform == ResponderPlatform.LINUX:
					sock.setsockopt(socket.SOL_SOCKET, 25, server_properties.bind_iface.encode())
					sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,1)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)		
				sock.bind(
					(
						str(bind_ip_override) if bind_ip_override is not None else str(server_properties.bind_addr), 
						int(server_properties.bind_port)
					)
				)

			elif server_properties.bind_family == socket.AF_INET6:
				if not socket.has_ipv6:
					raise Exception('IPv6 is NOT supported on this platform')
				if str(bind_ip_override) == '0.0.0.0':
					bind_ip_override = ipaddress.ip_address('::')
				sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
				sock.setblocking(False)
				if server_properties.platform in [ResponderPlatform.LINUX, ResponderPlatform.MAC]:
					sock.setsockopt(socket.SOL_SOCKET, 25, server_properties.bind_iface.encode())
					sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,1)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
				if server_properties.platform in [ResponderPlatform.LINUX, ResponderPlatform.MAC]:
					sock.bind(
						(
							str(bind_ip_override) if bind_ip_override is not None else str(server_properties.bind_addr), 
							int(server_properties.bind_port),
							server_properties.bind_iface_idx
						)
					)
				elif server_properties.platform == ResponderPlatform.WINDOWS:
					sock.bind(
						(
							str(bind_ip_override) if bind_ip_override is not None else str(server_properties.bind_addr), 
							int(server_properties.bind_port)
						)
					)
						
			else:
				raise Exception('Unknown IP version')
		else:
			raise Exception('Unknown protocol!')
		
		return sock
	except Exception as e:
		raise type(e)(str(e) +
				'Failed to set up socket for handler %s IP %s PORT %s FAMILY %s' % (\
						server_properties.serverhandler, \
						server_properties.bind_addr, \
						server_properties.bind_port, \
						server_properties.bind_family)\
				, sys.exc_info()[2]).with_traceback(sys.exc_info()[2])


class ConnectionClosed(Exception):
	pass

@asyncio.coroutine
def read_or_exc(reader, n, timeout = None):
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
	try:
		writer.write(data)
		yield from writer.drain()
	except:
		raise ConnectionClosed()

#thank you Python developers who after A FUCKING DECADE
#could not figure out a way to make your datetime.datetime
#object in a format that is reversible
#now it's either this bullshit "solution" OR installing a 3rd party
#lib that have to GUESS YOUR SHITTY FORMAT
#PS: "isoformat" doesn't even conforming to the ISO standard..
def isoformat2dt(isostr):
	dt, _, us= isostr.partition(".")
	dt= datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
	us= int(us.rstrip("Z"), 10)
	return dt + datetime.timedelta(microseconds=us)

#https://gist.github.com/ImmortalPC/c340564823f283fe530b
def hexdump( src, length=16, sep='.' ):
	'''
	@brief Return {src} in hex dump.
	@param[in] length	{Int} Nb Bytes by row.
	@param[in] sep		{Char} For the text part, {sep} will be used for non ASCII char.
	@return {Str} The hexdump
	@note Full support for python2 and python3 !
	'''
	result = [];

	# Python3 support
	try:
		xrange(0,1);
	except NameError:
		xrange = range;

	for i in xrange(0, len(src), length):
		subSrc = src[i:i+length];
		hexa = '';
		isMiddle = False;
		for h in xrange(0,len(subSrc)):
			if h == length/2:
				hexa += ' ';
			h = subSrc[h];
			if not isinstance(h, int):
				h = ord(h);
			h = hex(h).replace('0x','');
			if len(h) == 1:
				h = '0'+h;
			hexa += h+' ';
		hexa = hexa.strip(' ');
		text = '';
		for c in subSrc:
			if not isinstance(c, int):
				c = ord(c);
			if 0x20 <= c < 0x7F:
				text += chr(c);
			else:
				text += sep;
		result.append(('%08X:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i, hexa, text));

	return '\n'.join(result);