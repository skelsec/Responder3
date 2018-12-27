# https://www.ietf.org/rfc/rfc1939.txt
# https://www.ietf.org/rfc/rfc2449.txt
import hashlib
import io
import enum
import asyncio
from responder3.core.commons import read_element
from responder3.core.logging.log_objects import Credential
from responder3.core.asyncio_helpers import *


class POP3AuthMethod(enum.Enum):
	PLAIN = enum.auto()
	APOP = enum.auto()
	AUTH = enum.auto()


class POP3State(enum.Enum):
	AUTHORIZATION = enum.auto()
	TRANSACTION = enum.auto()
	UPDATE = enum.auto()


class POP3ResponseStatus(enum.Enum):
	OK = '+OK'
	ERR = '-ERR'
	XXXX = 'XXXX'


class POP3Command(enum.Enum):
	QUIT = enum.auto()
	STAT = enum.auto()
	LIST = enum.auto()
	RETR = enum.auto()
	DELE = enum.auto()
	NOOP = enum.auto()
	RSET = enum.auto()
	TOP = enum.auto()
	UIDL = enum.auto()
	USER = enum.auto()
	PASS = enum.auto()
	APOP = enum.auto()
	CAPA = enum.auto()
	AUTH = enum.auto()
	XXXX = enum.auto()
	STLS = enum.auto()


POP3TransactionStateCommands = [
	POP3Command.TOP,
	POP3Command.UIDL,
	POP3Command.STAT,
	POP3Command.LIST,
	POP3Command.RETR,
	POP3Command.DELE,
	POP3Command.NOOP,
	POP3Command.RSET,
	POP3Command.CAPA,
	POP3Command.QUIT,
]

POP3AuthorizationStateCommands = [
	POP3Command.USER,
	POP3Command.PASS,
	POP3Command.APOP,
	POP3Command.CAPA,
	POP3Command.QUIT,
	POP3Command.AUTH,
	POP3Command.STLS,
]

POP3UpdateStateCommands = [
	POP3Command.QUIT,
]


class POP3CommandParser:
	def __init__(self, encoding='ascii', timeout = 60):
		self.encoding = encoding
		self.timeout = timeout

	async def from_streamreader(self, reader):
		cmd = await readline_or_exc(reader, timeout=self.timeout)
		return self.from_bytes(cmd)

	def from_bytes(self, bbuff):
		return self.from_buffer(io.BytesIO(bbuff))

	def from_buffer(self, buff):
		line = buff.readline()
		try:
			command, *params = line.strip().decode(self.encoding).split(' ')
			if command in POP3Command.__members__:
				return POP3CMD[POP3Command[command]].from_bytes(line)
			else:
				return POP3XXXXCmd.from_bytes(line)
		except Exception as e:
			print(str(e))
			return POP3XXXXCmd.from_bytes(line)


class POP3QUITCmd:
	# NO ARGS
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.QUIT

	def from_buffer(buff, encoding='ascii'):
		return POP3QUITCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3QUITCmd()
		cmd.command = POP3Command[bbuff]
		return cmd

	def construct():
		cmd = POP3QUITCmd()
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % self.command.value).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'ARGS    : %s\r\n' % None
		return t

class POP3CAPACmd:
	# NO ARGS
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.CAPA

	def from_buffer(buff, encoding='ascii'):
		return POP3CAPACmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3CAPACmd()
		cmd.command = POP3Command[bbuff]
		return cmd

	def construct():
		cmd = POP3CAPACmd()
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % self.command.value).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		return t

class POP3STLSCmd:
	# NO ARGS
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.STLS

	def from_buffer(buff, encoding='ascii'):
		return POP3STLSCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3STLSCmd()
		cmd.command = POP3Command[bbuff]
		return cmd

	def construct():
		cmd = POP3STLSCmd()
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % self.command.value).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'ARGS    : %s\r\n' % None
		return t

class POP3STATCmd:
	# NO ARGS
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.STAT

	def from_buffer(buff, encoding='ascii'):
		return POP3STATCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3STATCmd()
		cmd.command = POP3Command[bbuff]
		return cmd

	def construct():
		cmd = POP3STATCmd()
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % self.command.value).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'ARGS    : %s\r\n' % None
		return t


class POP3LISTCmd:
	# optional argument for the messagenumber
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.LIST
		self.msgno = None

	def from_buffer(buff, encoding='ascii'):
		return POP3LISTCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3LISTCmd()
		t, bbuff = read_element(bbuff, toend=True)
		cmd.command = POP3Command[t]
		if bbuff.strip() != '':
			cmd.msgno, bbuff = read_element(bbuff, toend=True)
		return cmd

	def construct(msgno=None):
		cmd = POP3LISTCmd()
		cmd.msgno = msgno
		return cmd

	def to_bytes(self):
		if self.msgno is not None:
			return ('%s %s\r\n' % (self.command.value, self.msgno)).encode(self.encoding)
		else:
			return ('%s\r\n' % self.command.value).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'Msgno    : %s\r\n' % self.msgno
		return t


class POP3RETRCmd():
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.RETR
		self.msgno = None

	def from_buffer(buff, encoding='ascii'):
		return POP3RETRCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3RETRCmd()
		t, bbuff = read_element(bbuff, toend=True)
		cmd.command = POP3Command[t]
		if bbuff.strip() != '':
			cmd.msgno, bbuff = read_element(bbuff, toend=True)
		return cmd

	def construct(msgno):
		cmd = POP3RETRCmd()
		cmd.msgno = msgno
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % (self.command.value, self.msgno)).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'Msgno    : %s\r\n' % self.msgno
		return t


class POP3DELECmd():
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.DELE
		self.msgno = None

	def from_buffer(buff, encoding='ascii'):
		return POP3DELECmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3DELECmd()
		t, bbuff = read_element(bbuff, toend=True)
		cmd.command = POP3Command[t]
		cmd.msgno, bbuff = read_element(bbuff, toend=True)
		return cmd

	def construct(msgno):
		cmd = POP3DELECmd()
		cmd.msgno = msgno
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % (self.command.value, self.msgno)).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'Msgno    : %s\r\n' % self.msgno
		return t


class POP3TOPCmd():
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.TOP
		self.msgno = None
		self.numlines = None

	def from_buffer(buff, encoding='ascii'):
		return POP3TOPCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3TOPCmd()
		t, bbuff = read_element(bbuff)
		cmd.command = POP3Command[t]
		cmd.msgno, bbuff = read_element(bbuff)
		cmd.numlines, bbuff = read_element(bbuff, toend=True)
		return cmd

	def construct(msgno, numlines):
		cmd = POP3TOPCmd()
		cmd.msgno = msgno
		cmd.numlines = numlines
		return cmd

	def to_bytes(self):
		return ('%s %s %s\r\n' % (self.command.value, self.msgno, self.numlines)).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command  : %s\r\n' % self.command.name
		t += 'Msgno    : %s\r\n' % self.msgno
		t += 'Numlines : %s\r\n' % self.numlines
		return t


class POP3UIDLCmd():
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.UIDL
		self.msgno = None

	def from_buffer(buff, encoding='ascii'):
		return POP3UIDLCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3UIDLCmd()
		t, bbuff = read_element(bbuff, toend=True)
		cmd.command = POP3Command[t]
		if bbuff.strip() != '':
			cmd.msgno, bbuff = read_element(bbuff, toend=True)
		return cmd

	def construct(msgno):
		cmd = POP3UIDLCmd()
		cmd.msgno = msgno
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % (self.command.value, self.msgno)).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'Msgno    : %s\r\n' % self.msgno
		return t


class POP3NOOPCmd():
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.NOOP

	def from_buffer(buff, encoding='ascii'):
		return POP3NOOPCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3NOOPCmd()
		cmd.command = POP3Command[bbuff]
		return cmd

	def construct():
		cmd = POP3NOOPCmd()
		return cmd

	def to_bytes(self):
		return ('%s\r\n' % self.command.value).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'ARGS    : %s\r\n' % None
		return t

class POP3AUTHCmd:
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.AUTH
		self.auth_type = None

	def from_buffer(buff, encoding='ascii'):
		return POP3AUTHCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3AUTHCmd()
		t, bbuff = read_element(bbuff, toend=True)
		cmd.command = POP3Command[t]
		if bbuff.strip() != '':
			cmd.auth_type, bbuff = read_element(bbuff, toend=True)
		return cmd

	def construct(auth_type):
		cmd = POP3AUTHCmd()
		cmd.auth_type = auth_type
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % (self.command.value, self.auth_type)).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command   : %s\r\n' % self.command.name
		t += 'Auth-type : %s\r\n' % self.auth_type
		return t

class POP3USERCmd():
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.USER
		self.username = None

	def from_buffer(buff, encoding='ascii'):
		return POP3USERCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3USERCmd()
		t, bbuff = read_element(bbuff)
		cmd.command = POP3Command[t]
		cmd.username, bbuff = read_element(bbuff, toend=True)
		return cmd

	def construct(username):
		cmd = POP3USERCmd()
		cmd.username = username
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % (self.command.value, self.username)).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'Username    : %s\r\n' % self.username
		return t


class POP3PASSCmd():
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.PASS
		self.password = None

	def from_buffer(buff, encoding='ascii'):
		return POP3PASSCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3PASSCmd()
		t, bbuff = read_element(bbuff)
		cmd.command = POP3Command[t]
		cmd.password, bbuff = read_element(bbuff, toend=True)
		return cmd

	def construct(password):
		cmd = POP3PASSCmd()
		cmd.password = password
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % (self.command.value, self.password)).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'Password: %s\r\n' % self.password
		return t


class POP3APOPCmd():
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.APOP
		self.username = None
		self.digest = None

	def from_buffer(buff, encoding='ascii'):
		return POP3APOPCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3APOPCmd()
		t, bbuff = read_element(bbuff)
		cmd.command = POP3Command[t]
		cmd.username, bbuff = read_element(bbuff)
		cmd.digest, bbuff = read_element(bbuff, toend=True)
		return cmd

	def construct(username, digest):
		cmd = POP3APOPCmd()
		cmd.username = username
		cmd.digest = digest
		return cmd

	def to_bytes(self):
		return ('%s %s %s\r\n' % (self.command.value, self.username, self.digest)).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command  : %s\r\n' % self.command.name
		t += 'username : %s\r\n' % self.username
		t += 'Digest   : %s\r\n' % self.digest
		return t


class POP3RSETCmd():
	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.RSET

	def from_buffer(buff, encoding='ascii'):
		return POP3RSETCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3RSETCmd()
		cmd.command = POP3Command[bbuff]
		return cmd

	def construct():
		cmd = POP3RSETCmd()
		return cmd

	def to_bytes(self):
		return ('%s\r\n' % self.command.value).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'ARGS    : %s\r\n' % None
		return t


class POP3XXXXCmd():
	"""
	Generic catch-all for all unparsable command
	"""

	def __init__(self, encoding='ascii'):
		self.encoding = encoding
		self.command = POP3Command.XXXX
		self.data = None

	def from_buffer(buff, encoding='ascii'):
		return POP3RSETCmd.from_bytes(buff.readline(), encoding)

	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = POP3XXXXCmd()
		cmd.data = bbuff
		return cmd

	def construct(data):
		cmd = POP3XXXXCmd()
		cmd.data = data
		return cmd

	def to_bytes(self):
		return ('%s\r\n' % self.data).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'DATA    : %s\r\n' % self.data
		return t


class POP3ResponseParser():
	def __init__(self, encoding='ascii'):
		self.encoding = encoding

	# POP3ResponseStatus

	async def from_streamreader(self, reader, is_multiline=False):
		if is_multiline:
			resp = b''
			while True:
				t = await readline_or_exc(reader, timeout=self.timeout)
				resp += t
				if t.strip() == b'.':
					break
			return self.from_bytes(resp)

		else:
			resp = await readline_or_exc(reader, timeout=self.timeout)
			return self.from_bytes(resp)

	def from_bytes(self, bbuff, is_multiline=False):
		return self.from_buffer(io.BytesIO(bbuff), is_multiline)

	def from_buffer(self, buff, is_multiline=False):
		line = buff.readline()
		respcode, *params = line.strip().decode(self.encoding).split(' ')
		try:
			return POP3RESP[POP3ResponseStatus(respcode)].from_bytes(line)
		except Exception as e:
			print(str(e))
			return POP3XXXXResp.from_bytes(line)


class POP3XXXXResp:
	def __init__(self):
		self.status = POP3ResponseStatus.XXXX
		self.data = None

	@staticmethod
	def from_buffer(buff, encoding='ascii'):
		return POP3XXXXResp.from_bytes(buff.readline(), encoding)

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		resp = POP3XXXXResp()
		resp.data = bbuff.decode(encoding).strip()
		return resp

	def to_bytes(self):
		return ('%s\r\n' % self.data).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Response ==\r\n' % self.status.name
		t += 'DATA    : %s\r\n' % self.data
		return t


class POP3OKResp():
	def __init__(self,encoding = 'ascii'):
		self.encoding = encoding
		self.status = POP3ResponseStatus.OK
		self.params = None
		self.data = None

	@staticmethod
	def from_buffer(buff, encoding='ascii'):
		return POP3OKResp.from_bytes(buff.readline(), encoding)

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip().split('\r\n')
		resp = POP3OKResp()
		status, resp.params = read_element(bbuff[0], toend=True)
		resp.status = POP3ResponseStatus(status)
		if len(bbuff) > 1:
			resp.data = bbuff[1:]

		return resp

	@staticmethod
	def construct(params = '', data=None):
		resp = POP3OKResp()
		resp.params = params
		resp.data = data
		return resp

	def to_bytes(self):
		if self.data is None:
			if self.params is None:
				return ('%s\r\n' % self.status.value).encode(self.encoding)
			else:
				return ('%s %s\r\n' % (self.status.value, self.params)).encode(self.encoding)
		else:
			return

	def __repr__(self):
		t = '== POP3 %s Response ==\r\n' % self.status.name
		t += 'Params : %s\r\n' % self.params
		t += 'DATA    : %s\r\n' % self.data
		return t


class POP3ERRResp():
	def __init__(self,encoding = 'ascii'):
		self.encoding = encoding
		self.status = POP3ResponseStatus.OK
		self.params = None

	@staticmethod
	def from_buffer(buff, encoding='ascii'):
		return POP3ERRResp.from_bytes(buff.readline(), encoding)

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		resp = POP3ERRResp()
		status, resp.params = read_element(bbuff, toend=True)
		resp.status = POP3ResponseStatus(status)
		return resp

	@staticmethod
	def construct(params=None):
		resp = POP3ERRResp()
		resp.params = params
		return resp

	def to_bytes(self):
		if self.params is None:
			return ('%s\r\n' % self.status.value).encode(self.encoding)
		else:
			return ('%s %s\r\n' % (self.status.value, self.params)).encode(self.encoding)

	def __repr__(self):
		t = '== POP3 %s Response ==\r\n' % self.status.name
		t += 'Params : %s\r\n' % self.params
		return t


class POP3AuthStatus(enum.Enum):
	OK = enum.auto()
	NO = enum.auto()
	MORE_DATA_NEEDED = enum.auto()


class POP3AuthHandler:
	def __init__(self, authtype, creds=None, salt = None):
		if authtype == POP3AuthMethod.PLAIN:
			self.authahndler = POP3PlainAuth(creds)
		elif authtype == POP3AuthMethod.AUTH:
			self.authahndler = POP3AUTHAuth(creds)
		elif authtype == POP3AuthMethod.APOP:
			self.authahndler = POP3APOPAuth(creds, salt)
		else:
			raise NotImplementedError

	def do_AUTH(self, pop3cmd, salt = None):
		return self.authahndler.update_creds(pop3cmd)

#
#

class POP3AUTHAuth:
	def __init__(self, creds):
		self.creds = creds
		self.username = None
		self.password = None

	def update_creds(self, pop3cmd):
		if pop3cmd.command == POP3Command.AUTH:
			return POP3AuthStatus.MORE_DATA_NEEDED, b'\r\n'
		
		if not self.username:
			self.username = pop3cmd.username
			return POP3AuthStatus.MORE_DATA_NEEDED, POP3OKResp.construct('').to_bytes()

		elif not self.password:
			self.password = pop3cmd.password

		else:
			raise Exception('Wrong command for authentication!')

		if self.username is not None and self.password is not None:
			return self.verify_creds()

		else:
			return POP3AuthStatus.MORE_DATA_NEEDED, b'\r\n'

	def verify_creds(self):
		c = POP3PlainCred(self.username, self.password)
		if self.creds is None:
			return POP3AuthStatus.OK, c.toCredential()
		else:
			if c.username in self.creds:
				if self.creds[c.username] == c.password:
					return POP3AuthStatus.OK, c.toCredential()
			else:
				return POP3AuthStatus.NO, c.toCredential()

		return POP3AuthStatus.NO, c.toCredential()


class POP3APOPAuth:
	def __init__(self, creds, salt):
		self.creds = creds
		self.salt = salt
		self.digest = None
		self.username = None

	def update_creds(self, pop3cmd):
		if pop3cmd.command == POP3Command.APOP:
			self.username = pop3cmd.username
			self.digest = pop3cmd.digest
			return self.verify_creds()
		else:
			raise Exception('Wrong command for authentication!')

	def verify_creds(self):
		c = POP3APOPCred(self.username, self.digest, self.salt)
		if self.creds is None:
			return POP3AuthStatus.OK, c.toCredential()
		else:
			if c.username in self.creds:
				calc_digest = hashlib.md5(self.salt.encode() + self.creds[c.username].encode()).hexdigest()
				if calc_digest == self.digest:
					return POP3AuthStatus.OK, c.toCredential()

			else:
				return POP3AuthStatus.NO, c.toCredential()

		return POP3AuthStatus.NO, c.toCredential()


class POP3APOPCred:
	def __init__(self, username, digest, salt):
		self.username = username
		self.digest = digest
		self.salt = salt

	def toCredential(self):
		return Credential('APOP',
						  username=self.username,
						  fullhash='%s:%s:%s' % (self.username, self.digest, self.salt)
						  )


class POP3PlainAuth:
	def __init__(self, creds):
		self.creds = creds
		self.username = None
		self.password = None

	def update_creds(self, pop3cmd):
		if pop3cmd.command == POP3Command.USER:
			self.username = pop3cmd.username

		elif pop3cmd.command == POP3Command.PASS:
			self.password = pop3cmd.password

		else:
			raise Exception('Wrong command for authentication!')

		if self.username is not None and self.password is not None:
			return self.verify_creds()

		else:
			return POP3AuthStatus.MORE_DATA_NEEDED, POP3OKResp.construct('').to_bytes()

	def verify_creds(self):
		c = POP3PlainCred(self.username, self.password)
		if self.creds is None:
			return POP3AuthStatus.OK, c.toCredential()
		else:
			if c.username in self.creds:
				if self.creds[c.username] == c.password:
					return POP3AuthStatus.OK, c.toCredential()

			else:
				return POP3AuthStatus.NO, c.toCredential()

		return POP3AuthStatus.NO, c.toCredential()

class POP3PlainCred:
	def __init__(self, username, password):
		self.username = username
		self.password = password

	def toCredential(self):
		return Credential('PLAIN',
						  username=self.username,
						  password=self.password,
						  fullhash='%s:%s' % (self.username, self.password)
						  )


POP3RESP = {
	POP3ResponseStatus.OK : POP3OKResp,
	POP3ResponseStatus.ERR: POP3ERRResp,
}

POP3CMD = {
	POP3Command.QUIT: POP3QUITCmd,
	POP3Command.STAT: POP3STATCmd,
	POP3Command.LIST: POP3LISTCmd,
	POP3Command.RETR: POP3RETRCmd,
	POP3Command.DELE: POP3DELECmd,
	POP3Command.NOOP: POP3NOOPCmd,
	POP3Command.RSET: POP3RSETCmd,
	POP3Command.TOP : POP3TOPCmd,
	POP3Command.UIDL: POP3UIDLCmd,
	POP3Command.USER: POP3USERCmd,
	POP3Command.PASS: POP3PASSCmd,
	POP3Command.APOP: POP3APOPCmd,
	POP3Command.CAPA: POP3CAPACmd,
	POP3Command.XXXX: POP3XXXXCmd,
	POP3Command.AUTH: POP3AUTHCmd,
	POP3Command.STLS: POP3STLSCmd,
}
