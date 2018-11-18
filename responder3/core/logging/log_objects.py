import json
import enum
import datetime
import time

from responder3.core.commons import *

class LogObjectType(enum.Enum):
	LOGENTRY = 0
	PROXYDATA = 1
	CONNECTION = 3
	CONNECTION_OPENED = 4
	CONNECTION_CLOSED = 5
	CREDENTIAL = 6
	POISONRESULT = 7
	EMAILENTRY = 8
	TRAFFICLOG = 9
	REMOTELOG = 10

	
class RemoteLog:
	def __init__(self, rlog):
		self.remote_ip = rlog.remote_ip
		self.remote_port = rlog.remote_port
		self.client_id = rlog.client_id
		self.log_obj = logobj2type[LogObjectType(rlog.log_obj_type)].from_dict(rlog.log_obj)
		
	def __str__(self):
		return "[%s][%s:%s] %s" % (self.client_id, self.remote_ip, self.remote_port, str(self.log_obj))

	def to_dict(self):
		t = {}
		t['remote_ip'] = self.remote_ip
		t['remote_port'] = self.remote_port
		t['client_id'] = self.client_id
		t['log_obj'] = self.log_obj.to_dict()
		return t 

	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)
		
class LogEntry:
	"""
	Communications object that is used to pass log information to the LogProcessor
	"""
	def __init__(self, level, name, msg, connection = None):
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
		self.connection = connection

	def to_dict(self):
		t = {}
		t['level'] = self.level
		t['name'] = self.name
		t['msg'] = self.msg
		t['connection'] = self.connection.to_dict() if self.connection else None
		return t

	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)

	def __str__(self):
		t = '[%s]' % self.name
		if self.connection:
			t += '[%s]' % self.connection.get_local_print_address()
			if self.connection.remote_ip:
				t += '[%s]' % self.connection.get_remote_print_address()

		t += ' %s' % self.msg

		return t

		
	@staticmethod
	def from_dict(d):
		if 'connection' in d and d['connection']:
			return LogEntry( d['level'], d['name'], d['msg'], Connection.from_dict(d['connection']))
		else:
			return LogEntry( d['level'], d['name'], d['msg'], None)
		
		
	@staticmethod
	def from_json(data):
		return LogEntry.from_dict(json.loads(data))



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

		
class Credential:
	def __init__(self, credtype, domain = None, username = None, password = None, fullhash = None, module = None, connection = None):
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
		self.module = module
		self.connection = connection
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
		t['module'] = self.module
		t['connection'] = self.connection.to_dict()
		t['credtype'] = self.credtype
		t['domain'] = self.domain
		t['username'] = self.username
		t['password'] = self.password
		t['fullhash'] = self.fullhash
		t['module'] = self.module
		t['client_addr'] = self.client_addr
		t['client_rdns'] = self.client_rdns
		t['fingerprint'] = self.fingerprint
		return t

	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)
		
		
	@staticmethod
	def from_dict(d):
		cc = Credential( d['credtype'])
		cc.module = d['module']
		cc.connection = Connection.from_dict(d['connection'])
		cc.domain   = d['domain']
		cc.username = d['username']
		cc.password = d['password']
		cc.fullhash     = d['fullhash']
		cc.module   = d['module']
		cc.client_addr  = d['client_addr']
		cc.client_rdns  = d['client_rdns']
		cc.fingerprint = d['fingerprint']
		return cc
		
	@staticmethod
	def from_json(data):
		return Credential.from_dict(json.loads(data))

	def __str__(self):
		return '[%s][%s][%s][%s] %s' % (self.module, self.connection.get_local_print_address(), self.connection.get_remote_print_address(), 'CREDENTIAL', self.fullhash)


class PoisonResult:
	def __init__(self,connection, module = None):
		"""
		Container for messages captured or emitted by poisoner modules
		"""
		self.module = module
		self.connection = connection
		self.target = None
		self.request_name = None
		self.request_type = None
		self.poison_name = None
		self.poison_addr = None
		self.mode = None

	def to_dict(self):
		t = self.connection.to_dict()
		t['module'] = self.module
		t['connection'] = self.connection.to_dict()
		t['target'] = self.target
		t['request_name'] = self.request_name
		t['request_type'] = self.request_type
		t['poison_name'] = self.poison_name
		t['poison_addr'] = self.poison_addr
		t['mode'] = self.mode
		return t

	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)

	def __repr__(self):
		return str(self)
		
	@staticmethod
	def from_dict(d):
		cc = PoisonResult()
		cc.connection = Connection.from_dict(d['connection'])
		cc.module = d['module']
		cc.target = d['target']
		cc.request_name = d['request_name']
		cc.request_type = d['request_type']
		cc.poison_name = d['poison_name']
		cc.poison_addr = d['poison_addr']
		cc.mode = PoisonerMode(d['mode'])
		
		return cc
		
	@staticmethod
	def from_json(data):
		return PoisonResult.from_dict(json.loads(data))

	def __str__(self):
		return '%s %s %s' % (self.credtype, self.domain, self.fullhash)

	def __str__(self):
		if self.mode == PoisonerMode.ANALYSE:
			return '[%s] Recieved request from IP: %s to resolve: %s' % (self.module, self.target, self.request_name)
		else:
			return '[%s] Spoofing target: %s for the request: %s which matched the expression %s. Spoof address %s' % (self.module, self.target, self.request_name, self.poison_name, self.poison_addr)


class EmailEntry:
	def __init__(self, connection, module = None):
		"""
		Container for emails captured
		"""
		self.module = module
		self.connection = connection
		self.fromAddress = None #string
		self.toAddress   = None #list
		self.email       = None #email object (from the email package)



class ConnectionOpened:
	def __init__(self, connection, module = None):
		self.module = module
		self.connection = connection
		
	def to_dict(self):
		t = self.connection.to_dict()
		t['module'] = self.module
		return t
		
	def to_json(self):
		return json.dumps(self.to_dict(), cls = UniversalEncoder)
		
	@staticmethod
	def from_dict(d):
		return ConnectionOpened(Connection.from_dict(d), module= d['module'])
		
	@staticmethod
	def from_json(data):
		return ConnectionOpened.from_dict(json.loads(data))
		
	def __str__(self):
		return '[%s][%s][%s][%s]' % (self.module, self.connection.get_local_print_address(), self.connection.get_remote_print_address(), 'OPENED')

class ConnectionClosed:
	def __init__(self, connection, module = None):
		self.module = module
		self.connection = connection
		self.disconnect_time = datetime.datetime.utcnow()
		self.total_connection_time_s = (self.disconnect_time - self.connection.timestamp).total_seconds()
		
	def to_dict(self):
		t = self.connection.to_dict()
		t['total_connection_time_s'] = self.total_connection_time_s
		t['disconnect_time'] = self.disconnect_time
		t['module'] = self.module
		return t
		
	def to_json(self):
		return json.dumps(self.to_dict(), cls = UniversalEncoder)
		
	@staticmethod
	def from_dict(d):
		cc = ConnectionClosed( Connection.from_dict(d), module= d['module'])
		cc.disconnect_time = isoformat2dt(d['disconnect_time'])
		cc.total_connection_time_s = d['total_connection_time_s']
		return cc
		
	@staticmethod
	def from_json(data):
		return ConnectionClosed.from_dict(json.loads(data))
		
	def __str__(self):
		return '[%s][%s][%s][%s] Lasted %s seconds' % (self.module, self.connection.get_local_print_address(), self.connection.get_remote_print_address(), 'CLOSED', self.total_connection_time_s)

class TrafficLog:
	def __init__(self):
		self.module = None
		self.connection = None
		self.data_recv = {}
		self.unconsumed_buffer = b''
		self.data_sent = {}

	def to_dict(self):
		t = {}
		t['module'] = self.module
		t['connection'] = self.connection.to_dict()
		t['data_recv'] = {}
		t['data_sent'] = {}
		for date in self.data_recv:
			t['data_recv'][int(date.timestamp()*10**3)] = self.data_recv[date].hex()
		for date in self.data_sent:
			t['data_sent'][int(date.timestamp()*10**3)] = self.data_sent[date].hex()
		t['unconsumed_buffer'] = self.unconsumed_buffer.hex()
		return t

	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)

	@staticmethod
	def from_dict(d):
		t = TrafficLog()
		t.module = d['module']
		t.connection = Connection.from_dict(d['connection'])
		for date in d['data_recv']:
			t.data_recv[datetime.datetime.fromtimestamp(date/10**3)] = bytes.fromhex(d['data_recv'][date])
		for date in d['data_sent']:
			t.data_sent[datetime.datetime.fromtimestamp(date/10**3)] = bytes.fromhex(d['data_sent'][date])
		t.unconsumed_buffer = bytes.fromhex(d['unconsumed_buffer'])
		return t

	@staticmethod
	def from_json(data):
		return TrafficLog.from_dict(json.loads(data))

	def merge(self):
		allcom = []
		for date in self.data_recv:
			allcom.append((date, 'RECV', self.data_recv[date]))
		for date in self.data_sent:
			allcom.append((date, 'SENT', self.data_sent[date]))

		return sorted(allcom, key=lambda x: x[0])



	def get_loglines(self):
		for date, direction, data in self.merge():
			yield '[%s][%s][%s][TRAFFICLOG][%s][%s] %s' % (self.module, self.connection.get_local_print_address(), self.connection.get_remote_print_address(), direction, date, data.hex())

### needs to be at the bottom!!!
logobj2type = {
	LogObjectType.LOGENTRY : LogEntry,
	LogObjectType.PROXYDATA : ProxyData,
	LogObjectType.CONNECTION : Connection,
	LogObjectType.CONNECTION_OPENED : ConnectionOpened,
	LogObjectType.CONNECTION_CLOSED : ConnectionClosed,
	LogObjectType.CREDENTIAL : Credential,
	LogObjectType.POISONRESULT : PoisonResult,
	LogObjectType.EMAILENTRY : EmailEntry,
	LogObjectType.TRAFFICLOG : TrafficLog,
	LogObjectType.REMOTELOG : RemoteLog,
}

logobj2type_inv = {v: k for k, v in logobj2type.items()}

