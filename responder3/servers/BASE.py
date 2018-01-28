from abc import ABC, abstractmethod
import hashlib
import asyncio
import logging
import datetime
import enum
import socket
import os
import traceback


from responder3.utils import ServerProtocol

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
			self.rdns = self.rdnsd [self.remote_ip]
		
		else:
			try:
				self.rdns = socket.gethostbyaddr(self.remote_ip)[0]
			except Exception as e:
				pass

			self.rdnsd [self.remote_ip] = self.rdns

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
		m = hashlib.sha256()
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

class ResponderServer(ABC):
	"""
	Base class for TCP server. All server tamplates MUST inherit from this class
	Provides basic functionality to the server templates like logging etc.
	"""
	def __init__(self):
		self.port        = None
		self.loop        = None
		self.logQ        = None
		self.settings    = None
		self.rdnsd       = None
		self.bind_addr   = None
		self.bind_port   = None
		self.bind_family = None
		self.bind_proto  = None
		self.protocolSession = None

	def _setup(self, server, loop, logQ):
		self.bind_addr   = server.bind_addr
		self.bind_port   = server.bind_port
		self.bind_family = server.bind_family
		self.bind_proto  = server.proto
		self.loop        = loop
		self.logQ        = logQ
		self.settings    = server.settings
		self.rdnsd       = server.rdnsd
		self.setup()

	def run(self, ssl_context = None):
		"""
		TODO: SSL over UDP ?
		"""
		if self.bind_proto in [ServerProtocol.TCP, ServerProtocol.SSL]:
			coro = self.loop.create_server(
								protocol_factory=lambda: self.protocol(self),
								host=str(self.bind_addr), 
								port=self.bind_port,
								family=self.bind_family,
								reuse_address=True,
								reuse_port=True,
								ssl=ssl_context
			)

		elif self.bind_proto == ServerProtocol.UDP:
			coro = self.loop.create_datagram_endpoint(
							protocol_factory=lambda: self.protocol(self),
							local_addr=(str(self.bind_addr), self.bind_port),
							family=self.bind_family
			)

		return self.loop.run_until_complete(coro)

	def log(self, level, message, session = None):
		"""
		Create a log message and send it to the LogProcessor for procsesing
		"""
		if session is None or session.connection.remote_ip == None:
			message = '[INIT] %s' %  message
		else:	
			message = '[%s:%d] %s' % (session.connection.remote_ip, session.connection.remote_port, message)
		self.logQ.put(LogEntry(level, self.modulename(), message))

	def logResult(self, session, resultd):
		"""
		Create a Result message and send it to the LogProcessor for procsesing
		"""
		resultd['module'] = self.modulename()
		resultd['client'] = session.connection.remote_ip
		self.logQ.put(Result(resultd))

	def logConnection(self, session):
		"""
		Create a Connection message and send it to the LogProcessor for procsesing
		connection: A connection object that holds the connection info for the client
		"""
		if session.connection.status == ConnectionStatus.OPENED or session.connection.status == ConnectionStatus.STATELESS:
			self.log(logging.INFO, 'New connection opened', session)
		elif session.connection.status == ConnectionStatus.CLOSED:
			self.log(logging.INFO, 'Connection closed', session)
		self.logQ.put(session.connection)

	def logPoisonResult(self, session, requestName = None, poisonName = None, poisonIP = None):
		self.log(logging.INFO, 'Resolv request in!', session)
		pr = PoisonResult()
		pr.module = self.modulename()
		pr.target = session.connection.remote_ip
		pr.request_name = requestName
		pr.request_type = None
		pr.poison_name = poisonName
		pr.poison_addr = poisonIP
		pr.mode = self.settings['mode']

		self.logQ.put(pr)

	def logEmail(self, session, emailEntry):
		self.log(logging.INFO, 'You got mail!', session)
		self.logQ.put(emailEntry)

	def setup(self):
		"""
		Override this method in the server template if additional setup setps are needed
		"""
		pass

	@abstractmethod
	def modulename(self):
		"""
		!!This method must be overridden by the server template to return a string that identifies your server 
		"""
		pass

	@abstractmethod
	def handle(self):
		"""
		The main method of the server template. This will be called each time a new packet is available
		!!This method must be overridden by the server template!!
		"""
		pass

class ProtocolSession():
	"""
	Holds all session-related information for the current connection,
	use this object to store intermediate values like authentication info, intermediate buffers etc.
	This object is the only one that will retrain the data what you are passing to the ResponderServer.handle() and above!
	Inherit form this object in your server template if additional session info is desired
	"""
	def __init__(self, rdnsd):
		self.connection = Connection(rdnsd)



class ResponderProtocolTCP(asyncio.Protocol):
	"""
	Base class for all TCP based server templates. This class handles the actual connections and maintains the session information.
	The 
	"""
	def __init__(self, server):
		asyncio.Protocol.__init__(self)
		self._server         = server
		self._session        = None
		self._buffer_maxsize = 10*1024 #if the buffer becomes bigger than this, an exception will be raised
		self._parsed_length  = None    #most TCP based protocols contain a length of the data to be read, reaching this length will trigger a call to _parsebuff
		self._transport      = None
		self._buffer         = b''
		


	def connection_made(self, transport):
		"""
		DO NOT OVERRIDE THIS FUNCTION
		If additional functionality is needed (like sending server greeting) implement it by overriding the _connection_made function
		"""
		self._session.connection.setupTCP(transport.get_extra_info('socket'), ConnectionStatus.OPENED)
		self._server.logConnection(self._session)
		self._transport = transport
		self._connection_made()

	def data_received(self, raw_data):
		"""
		DO NOT OVERRIDE THIS FUNCTION
		Override the _parsebuff function that will be called when data is available
		"""
		try:
			self._buffer += raw_data
			if len(self._buffer) >= self._buffer_maxsize:
				raise Exception('Input data too large!')
		
			if 'R3DEEPDEBUG' in os.environ:
				#FOR DEBUG AND DEVELOPEMENT PURPOSES ONLY!!!
				self._server.log(logging.INFO,'Buffer contents before parsing: %s' % (self._buffer.hex()), self._session)

			
			self._parsebuff()

			if 'R3DEEPDEBUG' in os.environ:
				#FOR DEBUG AND DEVELOPEMENT PURPOSES ONLY!!!
				self._server.log(logging.INFO,'Buffer contents after parsing: %s' % (self._buffer.hex()), self._session)

		
		except Exception as e:
			traceback.print_exc()
			self._server.log(logging.INFO, 'Data reception failed! Reason: %s' % str(e), self._session)
			
			

	def connection_lost(self, exc):
		self._session.connection.status = ConnectionStatus.CLOSED
		self._server.logConnection(self._session)
		self._connection_lost(exc)

	## Override this to access to connection lost function
	def _connection_lost(self, exc):
		return

	## Override this to start handling the buffer, the data is in self._buffer as a string!
	def _parsebuff(self):
		return

	## Override this to start handling the buffer
	def _connection_made(self):
		return

class ResponderProtocolUDP(asyncio.DatagramProtocol):
	
	def __init__(self, server):
		asyncio.DatagramProtocol.__init__(self)
		self._server         = server
		self._session        = None
		self._buffer_maxsize = 10*1024 #if the buffer becomes bigger than this, an exception will be raised
		self._transport      = None
		self._buffer         = b''

	def connection_made(self, transport):
		self._transport = transport

	def datagram_received(self, raw_data, addr):
		self._session.connection.setupUDP(self._transport.get_extra_info('socket'), addr, ConnectionStatus.STATELESS)
		try:

			self._buffer += raw_data
			if len(self._buffer) >= self._buffer_maxsize:
				raise Exception('Input data too large!')
		
			if 'R3DEEPDEBUG' in os.environ:
				#FOR DEBUG AND DEVELOPEMENT PURPOSES ONLY!!!
				self._server.log(logging.INFO,'Buffer contents before parsing: %s' % (self._buffer.hex()), self._session)

			
			self._parsebuff(addr)

			if 'R3DEEPDEBUG' in os.environ:
				#FOR DEBUG AND DEVELOPEMENT PURPOSES ONLY!!!
				self._server.log(logging.INFO,'Buffer contents after parsing: %s' % (self._buffer.hex()), self._session)

		
		except Exception as e:
			traceback.print_exc()
			self._server.log(logging.INFO, 'Data reception failed! Reason: %s' % str(e), self._session)





	## Override this to start handling the buffer, the data is in self._buffer as a string!
	def _parsebuff(addr):
		return

	## Override this to start handling the buffer
	def _connection_made():
		return