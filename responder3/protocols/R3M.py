from abc import ABC, abstractmethod
import enum
import json
import io
import asyncio

from responder3.core.commons import UniversalEncoder

class R3CommandType(enum.Enum):
	R3_START = enum.auto()
	R3_START_REP = enum.auto()
	R3_STOP = enum.auto()
	R3_STOP_REP = enum.auto()
	SERVER_START = enum.auto()
	SERVER_START_REP = enum.auto()
	SERVER_STOP = enum.auto()
	SERVER_STOP_REP = enum.auto()
	GET_SERVER_LIST = enum.auto()
	GET_SERVER_LIST_REP = enum.auto()
	GET_SERVER_INFO = enum.auto()
	GET_SERVER_INFO_REP = enum.auto()
	SEND_SERVER_CMD = enum.auto()
	SEND_SERVER_CMD_REP = enum.auto()
	SUBSCIRBE_LOG = enum.auto()
	SUBSCIRBE_LOG_REP = enum.auto()


class Responder3Command(ABC):
	def __init__(self, cmd):
		self.command = cmd

	@abstractmethod
	def to_dict(self):
		pass

	@abstractmethod
	def from_dict(d):
		pass

	def to_json(self):
		return json.dumps(self.to_dict(), cls=UniversalEncoder)

	def to_bytes(self):
		data = self.to_json().encode()
		length = len(data).to_bytes(4, byteorder='big', signed=False)
		return length + data

	@staticmethod
	async def from_streamreader(reader):
		t = await reader.readexactly(4)
		length = int.from_bytes(t, byteorder='big', signed=False)
		data = await reader.readexactly(length)
		return Responder3Command.from_bytes(t + data)


	@staticmethod
	def from_bytes(bbuff):
		return Responder3Command.from_buff(io.BytesIO(bbuff))

	@staticmethod
	def from_buff(buff):
		length = int.from_bytes(buff.read(4), byteorder='big', signed=False)
		raw_data = buff.read(length)
		data = json.loads(raw_data)
		if 'command' not in data:
			return None
		command = R3CMD[R3CommandType(data['command'])].from_dict(data)
		return command


class R3StartCommand(Responder3Command):
	def __init__(self):
		Responder3Command.__init__(self, R3CommandType.R3_START)
		self.responder_config = None

	def to_dict(self):
		t = {}
		t['command'] = self.command
		t['responder_config'] = self.responder_config
		return t

	def from_dict(d):
		cmd = R3StartCommand()
		cmd.responder_config = d['responder_config']
		return cmd


class R3StopCommand(Responder3Command):
	def __init__(self):
		Responder3Command.__init__(self, R3CommandType.R3_STOP)

	def to_dict(self):
		t = {}
		t['command'] = self.command
		return t

	def from_dict(d):
		cmd = R3StopCommand()
		return cmd


class R3ServerListCommand(Responder3Command):
	def __init__(self):
		Responder3Command.__init__(self, R3CommandType.GET_SERVER_LIST)

	def to_dict(self):
		t = {}
		t['command'] = self.command
		return t

	def from_dict(d):
		cmd = R3ServerListCommand()
		return cmd

class R3ServerListReply(Responder3Command):
	def __init__(self):
		Responder3Command.__init__(self, R3CommandType.GET_SERVER_LIST_REP)
		self.servers = None

	@staticmethod
	def construct(servers):
		r = R3ServerListReply()
		r.servers = servers
		return r

	def to_dict(self):
		t = {}
		t['command'] = self.command
		t['servers'] = self.servers
		return t

	def from_dict(d):
		cmd = R3ServerListCommand()
		return cmd

class R3GetServerInfoCommand(Responder3Command):
	def __init__(self):
		Responder3Command.__init__(self, R3CommandType.GET_SERVER_INFO)
		self.task_id = None

	def to_dict(self):
		t = {}
		t['command'] = self.command
		t['task_id'] = self.task_id

		return t

	def from_dict(d):
		cmd = R3ServerListCommand()
		return cmd

R3CMD = {
	R3CommandType.R3_START: R3StartCommand,
	R3CommandType.R3_STOP: R3StopCommand,
	R3CommandType.GET_SERVER_LIST : R3ServerListCommand,
	R3CommandType.GET_SERVER_LIST_REP : R3ServerListReply,
	R3CommandType.GET_SERVER_INFO : R3GetServerInfoCommand,
}