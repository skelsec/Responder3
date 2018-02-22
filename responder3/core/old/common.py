import os
import queue
import base64
import enum
import datetime
import socket
import errno
import threading
from multiprocessing import Manager
from multiprocessing.managers import BaseManager

from responder3.crypto.hashing import *


#class QueueManager(BaseManager): pass


#DEFAULT SETTINGS
commonManager = None
logQueue = None #shared queue foir logging
rdnsLookupDict = None #shared dictionary across all processes to speed up rdns resolution
logQueueAddress = ('127.0.0.1', 50001)
logQueueAuthKey = b'#SuperSecretAuthKey!'
commonServerThread = None
#getting configuration settings

if 'R3LOGQUEUEADDRESS' is os.environ:
	addr = base64.b64decode(os.environ['R3LOGQUEUEADDRESS']).decode()
	marker = addr.rfind(':')
	logQueueAddress = (addr[:marker], int(addr[marker+1:]))
if 'R3LOGQUEUEAUTHKEY' is os.environ:
	logQueueAuthKey = base64.b64decode(os.environ['R3LOGQUEUEAUTHKEY'])

def start_common(address = logQueueAddress, authkey = logQueueAuthKey):
	commonManager = BaseManager(address=address, authkey=authkey)
	rdnsLookupDict = {}
	logQueue = queue.Queue()
	commonManager.register('get_logQueue', callable=lambda:logQueue)
	commonManager.register('get_rdnsLookupDict', callable=lambda:rdnsLookupDict)
	#logQueueManager = QueueManager(address=address, authkey=authkey)
	commonManagerServer = commonManager.get_server()
	commonServerThread = threading.Thread(target=commonManagerServer.serve_forever, daemon=True)
	commonServerThread.start()
	
	os.environ['R3LOGQUEUEADDRESS'] = base64.b64encode(b'%b:%b' % (address[0].encode(),str(address[1]).encode())).decode()
	os.environ['R3LOGQUEUEAUTHKEY'] = base64.b64encode(authkey).decode()

def get_logQueue(address = logQueueAddress, authkey = logQueueAuthKey):
	m = BaseManager(address=address, authkey=authkey)
	m.connect()
	logQueue = m.get_logQueue()
	return logQueue

def get_rdnsLookupDict(address = logQueueAddress, authkey = logQueueAuthKey):
	m = BaseManager(address=address, authkey=authkey)
	m.connect()
	rdnsLookupDict = m.get_rdnsLookupDict()
	return rdnsLookupDict

"""
try:
	print('Connecting to logQueue!')
	connect_logQueue()
	print('Connected to logQueue!')
except socket.error as serr:
	if serr.errno != errno.ECONNREFUSED:
		raise serr
"""
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

class Connection():
	"""
	Keeps all the connection related information that is used for logging and/or connection purposes
	rdnsd: multiprocessing shared dictionary of the rds-ip pairs that have already been resolved
	"""
	def __init__(self, rdnsd):
		self.status      = None
		self.rdnsd       = rdnsd
		self.rdns        = None
		self.remote_ip   = None
		self.remote_port = None
		self.local_ip    = None
		self.local_port  = None
		self.timestamp   = None


	def setupTCP(self, soc, status):
		"""
		Gets the connection info for a TCP session
		soc : the current socket
		status: ConnectionStatus

		"""
		self.timestamp = datetime.datetime.utcnow()
		self.remote_ip, self.remote_port = soc.getpeername()
		self.local_ip, self.local_port   = soc.getsockname()
		self.lookupRDNS()

	def setupUDP(self, soc, remoteAddr, status):
		"""
		Gets the connection info for a UDP session
		localAddr: socket,port tuple for the local server
		localAddr: socket,port tuple for the remote client
		"""
		self.timestamp = datetime.datetime.utcnow()
		self.local_ip, self.local_port   = soc.getsockname()
		self.remote_ip, self.remote_port = remoteAddr
		self.lookupRDNS()
		


	def lookupRDNS(self):
		"""
		Reolves the remote host's IP address to a DNS address. 
		First checks if the address has already been resolved by polling the shared rdns dictionary
		"""
		if self.remote_ip in self.rdnsd :
			self.rdns = self.rdnsd[self.remote_ip]
		
		else:
			try:
				self.rdns = socket.gethostbyaddr(self.remote_ip)[0]
			except Exception as e:
				pass

			self.rdnsd[self.remote_ip] = self.rdns

	def getRemoteAddress(self):
		return (self.remote_ip, self.remote_port)

	def toDict(self):
		t = {}
		t['status']      = self.status
		t['rdns']        = self.rdns
		t['remote_ip']   = self.remote_ip
		t['remote_port'] = self.remote_port
		t['local_ip']    = self.local_ip
		t['local_port']  = self.local_port
		t['timestamp']   = self.timestamp
		return t

	def __repr__(self):
		return str(self)

	def __str__(self):
		if self.rdns != '':
			return '[%s] %s:%d -> %s:%d' % (self.timestamp.isoformat(), self.rdns, self.remote_port, self.local_ip,self.local_port )
		else:
			return '[%s] %s:%d -> %s:%d' % (self.timestamp.isoformat(), self.remote_ip, self.remote_port, self.local_ip,self.local_port )

class PoisonerMode(enum.Enum):
	SPOOF = enum.auto()
	ANALYSE = enum.auto()

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

class Result():
	"""
	Communications object that is used to pass  authentication information to the LogProcessor
	"""
	def __init__(self, data = None):
		self.module    = None
		self.type      = None 
		self.client    = None
		self.user      = None
		self.cleartext = None
		self.fullhash  = None

		self.fingerprint = None

		if data is not None:
			self.parse(data)

	def parse(self,data):
		m = sha256()
		self.module    = data['module']
		m.update(self.module.encode())
		self.type  = data['type'] 
		m.update(self.type.encode())
		self.client    = data['client']
		m.update(self.client.encode())
		self.user      = data.get('user')
		if self.user is not None:
			m.update(self.user.encode())
		self.cleartext = data.get('cleartext')
		if self.cleartext is not None:
			m.update(self.cleartext.encode())
		self.fullhash  = data.get('fullhash')
		##some types needs to be excluded because they relay on some form of randomness in the auth protocol, 
		##yielding different fullhash data for the same password
		if self.fullhash is not None and self.type not in ['NTLMv1','NTLMv2']:
			m.update(self.fullhash.encode())

		self.fingerprint = m.hexdigest()

	def toDict(self):
		t = {}

		t['module'] = self.module
		t['type'] = self.type
		t['client'] = self.client
		t['user'] = self.user
		t['cleartext'] = self.cleartext
		t['fullhash'] = self.fullhash

		t['fingerprint'] = self.fingerprint
		return t

	def __eq__(self, other):
		return self.fingerprint == other.fingerprint

	def __ne__(self, other):
		return self.fingerprint != other.fingerprint

class EmailEntry():
	"""
	If the SMTP server recieved an email it's sent to the log queue for processing
	"""
	def __init__(self):
		self.fromAddress = None #string
		self.toAddress   = None #list
		self.email       = None #email object (from the email package)