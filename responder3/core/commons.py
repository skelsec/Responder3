#!/usr/bin/env python
import os
import sys
import enum
import json
import atexit
import datetime
import socket
import platform
import traceback
import ipaddress


from responder3.crypto.hashing import *
import asyncio


class ConnectionStatus(enum.Enum):
	OPENED = 0
	CLOSED = 1
	STATELESS = 3


class ConnectionFactory:
	def __init__(self, rdnsd, rdns_resolver):
		"""
		Creates Connetion object from the socket input.
		:param rdnsd: shared dictionary to speed up the rdns lookup
		:type rdnsd: dict created via multiprocessing.Manager()
		"""
		self.rdnsd = rdnsd
		self.resolver = rdns_resolver
		self.connection_id = 0
		

	async def from_streamwriter(self, writer):
		"""
		Creates Connection object from streamwriter
		:param writer: Streamwriter
		:type writer: asyncio.Streamwriter.
		:return: responder3.core.commons.Connection.
		"""
		protocoltype = writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
		cid = self.connection_id
		self.connection_id += 1
		con = Connection()
		con.writer = writer
		con.connection_id = cid
		con.local_ip, con.local_port   = writer.get_extra_info('sockname')
		con.remote_ip, con.remote_port = writer.get_extra_info('peername')
		
		await self.lookup_rdns(con)
		return con
		
	async def lookup_rdns(self, con):
		"""
		Resolves the remote host's IP address to a DNS address.
		First checks if the address has already been resolved by looking it up in the shared rdns dictionary
		:param con: The Connection object specifies the connection settings
		:type con: Connection
		:return: Nothing
		"""
		
		"""
		#failback for rdns resolution
		#this will work, but make the whole app slow
		
		if con.remote_ip in self.rdnsd:
			con.remote_dns = self.rdnsd[con.remote_ip]
		
		else:
			try:
				con.remote_dns = socket.gethostbyaddr(con.remote_ip)[0]
			except Exception as e:
				pass

			self.rdnsd[con.remote_ip] = con.remote_dns
		"""
		
		if con.remote_ip in self.rdnsd:
			con.remote_dns = self.rdnsd[con.remote_ip]
			
		else:
			con.remote_dns = await self.resolver.resolve(con.remote_ip)
			print(con.remote_dns)
			self.rdnsd[con.remote_ip] = con.remote_dns
		

		
class Connection:
	def __init__(self):
		"""
		Keeps all the connection related information that is used for logging and/or connection purposes
		"""
		self.connection_id = None
		self.remote_ip   = None
		self.remote_dns  = None
		self.remote_port = None
		self.local_ip    = None
		self.local_port  = None
		self.timestamp   = datetime.datetime.utcnow()
		self.writer = None

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
		t['connection_id'] = self.connection_id
		t['remote_ip']   = self.remote_ip
		t['remote_port'] = self.remote_port
		t['remote_dns']  = self.remote_dns
		t['local_ip']    = self.local_ip
		t['local_port']  = self.local_port
		t['timestamp']   = self.timestamp
		return t

	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)
		
	@staticmethod
	def from_dict(d):
		c = Connection()
		c.connection_id = d['connection_id']
		c.remote_ip   = d['remote_ip']
		c.remote_dns  = d['remote_dns']
		c.remote_port = d['remote_port']
		c.local_ip    = d['local_ip']
		c.local_port  = d['local_port']
		c.timestamp   = isoformat2dt(d['timestamp'])
		return c
		
		
	@staticmethod
	def from_json(data):
		return Connection.from_dict(json.loads(data))

	def __repr__(self):
		return str(self)

	def __str__(self):
		if self.remote_dns is not None and self.remote_dns != 'NA':
			return '[%s] %s:%d -> %s' % (self.timestamp.isoformat(), self.remote_dns, self.remote_port, self.get_local_print_address())
		else:
			return '[%s] %s-> %s' % (self.timestamp.isoformat(), self.get_remote_print_address(), self.get_local_print_address())


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
		elif isinstance(obj, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
			return str(obj)
		elif hasattr(obj, 'to_dict'):
			return obj.to_dict()
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
	return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)


class PoisonerMode(enum.Enum):
	"""
	Enum to specify the posioner module's mode of operation
	"""
	SPOOF = 'SPOOF'
	ANALYSE = 'ANALYSE'


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
	"SSH"  : [(22, 'tcp')],
	"TELNET"  : [(23, 'tcp')],
	"HTTP" : [(80, 'tcp')],
	"KERBEROS": [(88, 'tcp')],
	"HTTPS": [(443, 'tcp')],
	"FTP"  : [(21, 'tcp')],
	"SMTP" : [(25, 'tcp')],
	"POP3" : [(110, 'tcp')],
	"POP3S": [(995, 'tcp')],
	"IMAP" : [(143, 'tcp')],
	"IMAPS": [(993, 'tcp')],
	"SMB"  : [(445, 'tcp')],
	"LDAP" : [(389, 'tcp')],
	"RLOGIN" : [(513, 'tcp')],
	"LDAPS" : [(636, 'tcp')],
	"NBTNS": [(137, 'udp')],
	"SOCKS5":[(1080, 'tcp')],
	"MSSQL":[(1433, 'tcp')],
	"TNS":[(1521, 'tcp')],
	"MYSQL":[(3306, 'tcp')],
	"VNC":[(5900, 'tcp')],
	"SIP":[(5060, 'tcp')], #UDP maybe?
	"SIPS":[(5061, 'tcp')],
	"LLMNR": [(5355, 'udp')],
	"MDNS" : [(5353, 'udp')],
	"HTTPProxy":[(8080, 'tcp')],
	"R3M":[(55551,'tcp')]
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


def tracefunc(frame, event, arg, indent=[0]):
	if event == "call":
		indent[0] += 2
		print("-" * indent[0] + "> call function", frame.f_code.co_name)
	elif event == "return":
		print("<" + "-" * indent[0], "exit function", frame.f_code.co_name)
		indent[0] -= 2
	return tracefunc
	
