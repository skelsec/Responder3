import json
import enum

from responder3.core.commons import *

class R3ClientCommsClass:
	def to_dict(self):
		t = {}
		t['cmd_id'] = r3cli2cmd_inv[type(self)].value
		
		for name in self.__dict__:
			t[name] = getattr(self, name)
		return t
		
	def from_dict(self, d):
		for name in self.__dict__:
			setattr(self, name, d[name])

	def from_json(self, data):
		self.to_dict(json.loads(data))
		
	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)
		
class R3ClientCommsClassLoader:
	def __init__(self):
		self.cmdtype_enum = R3ClientCommand
		self.lookup_table = r3cli2cmd #cmdid -> object
		
	def from_dict(self, d):
		obj = self.lookup_table[self.cmdtype_enum(d['cmd_id'])]()
		obj.from_dict(d)
		return obj
		
	def from_json(self, data):
		return self.from_dict(json.loads(data))
		

class R3ClientCommand(enum.Enum):
	SHUTDOWN = 0
	STOP_SERVER = 1
	STOP_SERVER_RPLY = 2
	LIST_SERVERS = 3
	LIST_SERVERS_RPLY = 4
	CREATE_SERVER = 5
	CREATE_SERVER_RPLY = 6
	LOG = 7
	LIST_INTERFACES = 8
	LIST_INTERFACES_RPLY = 9
	
class R3CliShutdownCmd(R3ClientCommsClass):
	pass
	
class R3CliServerStopCmd(R3ClientCommsClass):
	def __init__(self, server_id = None):
		self.server_id = server_id
	
class R3CliServerStopRply(R3ClientCommsClass):
	def __init__(self, remote_ip = None, remote_port = None, status = None):
		self.remote_ip = remote_ip
		self.remote_port = remote_port
		self.status = status
	
class R3CliListServersCmd(R3ClientCommsClass):
	pass
	
class R3CliListServersRply(R3ClientCommsClass):
	def __init__(self, remote_ip = None, remote_port = None, servers = None):
		self.remote_ip = remote_ip
		self.remote_port = remote_port
		self.servers = servers
	
class R3CliCreateServerCmd(R3ClientCommsClass):
	def __init__(self, server_config = None):
		self.server_config = server_config
	
class R3CliCreateServerRply(R3ClientCommsClass):
	def __init__(self, remote_ip = None, remote_port = None, server_id = None, status = None):
		self.remote_ip = remote_ip
		self.remote_port = remote_port
		self.server_id = server_id
		self.status = data
		
class R3CliLog(R3ClientCommsClass):
	def __init__(self, remote_ip = None, remote_port = None, log_obj_type = None, log_obj = None):
		self.remote_ip = remote_ip
		self.remote_port = remote_port
		self.log_obj_type = log_obj_type
		self.log_obj = log_obj

class R3CliListInterfacesCmd(R3ClientCommsClass):
	pass

class R3CliListInterfacesRply(R3ClientCommsClass):
	def __init__(self, remote_ip = None, remote_port = None, interfaces = None):
		self.remote_ip = remote_ip
		self.remote_port = remote_port
		self.interfaces = interfaces
		
r3cli2cmd = {
	R3ClientCommand.SHUTDOWN : R3CliShutdownCmd,
	R3ClientCommand.STOP_SERVER : R3CliServerStopCmd,
	R3ClientCommand.STOP_SERVER_RPLY : R3CliServerStopRply,
	R3ClientCommand.LIST_SERVERS : R3CliListServersCmd,
	R3ClientCommand.LIST_SERVERS_RPLY : R3CliListServersRply,
	R3ClientCommand.CREATE_SERVER : R3CliCreateServerCmd,
	R3ClientCommand.CREATE_SERVER_RPLY : R3CliCreateServerRply,
	R3ClientCommand.LOG : R3CliLog,
	R3ClientCommand.LIST_INTERFACES : R3CliListInterfacesCmd,
	R3ClientCommand.LIST_INTERFACES_RPLY : R3CliListInterfacesRply,
}

r3cli2cmd_inv = {v: k for k, v in r3cli2cmd.items()}
