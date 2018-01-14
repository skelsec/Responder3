import io
import enum

class POP3State(enum.Enum):
	AUTHORIZATION = enum.auto()
	TRANSACTION   = enum.auto()
	UPDATE        = enum.auto()

class POP3ResponseStatus(enum.Enum):
	OK  = '+OK'
	ERR = '-ERR'

class POP3Command(enum.Enum):
	QUIT = enum.auto()
	STAT = enum.auto()
	LIST = enum.auto()
	RETR = enum.auto()
	DELE = enum.auto()
	NOOP = enum.auto()
	RSET = enum.auto()
	TOP  = enum.auto()
	UIDL = enum.auto()
	USER = enum.auto()
	PASS = enum.auto()
	APOP = enum.auto()
	XXXX = enum.auto()

class POP3CommandParser():
	def __init__(self, strict = False, encoding = 'ascii'):
		self.pop3command = None
		self.strict      = strict
		self.encoding    = encoding

	def parse(self, buff):
		raw = buff.readline()
		try:
			temp = raw[:-2].decode('ascii').split(' ')
			print(temp)
			command = POP3Command[temp[0]]
			if command == POP3Command.QUIT:
				self.pop3command = POP3QUITCommand()
			elif command == POP3Command.STAT:
				self.pop3command = POP3STATCommand()
			elif command == POP3Command.LIST:
				self.pop3command = POP3LISTCommand()
			elif command == POP3Command.RETR:
				self.pop3command = POP3RETRCommand()
			elif command == POP3Command.DELE:
				self.pop3command = POP3DELECommand()
			elif command == POP3Command.TOP:
				self.pop3command = POP3TOPCommand()
			elif command == POP3Command.UIDL:
				self.pop3command = POP3UIDLCommand()
			elif command == POP3Command.NOOP:
				self.pop3command = POP3NOOPCommand()
			elif command == POP3Command.USER:
				self.pop3command = POP3USERCommand(temp[1])
			elif command == POP3Command.PASS:
				self.pop3command = POP3PASSCommand(temp[1])
			elif command == POP3Command.APOP:
				self.pop3command = POP3APOPCommand()
			elif command == POP3Command.RSET:
				self.pop3command = POP3RSETCommand()
			else:
				self.smtpcommand = POP3XXXXCommand()
				self.smtpcommand.raw_data = raw

		except Exception as e:
			print(str(e))
			self.pop3command = POP3XXXXCommand()
			self.pop3command.raw_data = raw

		return self.pop3command

class POP3CommandBase():
	def __init__(self):
		self.command = None
		self.params  = None

	def __repr__(self):
		t  = '== POP3 Command ==\r\n' 
		t += 'Command : %s\r\n' % self.command.name
		t += 'ARGS    : %s\r\n' % ''.join(self.params)
		return t
	
	def toBytes(self):
		if self.params is None:
			return self.code.name.encode(self.encoding) + b'\r\n'
		elif len(self.params) == 1:
			return self.code.name.encode(self.encoding) + b' ' + self.params[0] + b'\r\n'
		else:
			return self.code.name.encode(self.encoding) + b' ' + self.params[0] + b'\r\n' + b'\r\n'.join(self.params[1:]) + b'.\r\n'


class POP3QUITCommand(POP3CommandBase):
	#NO ARGS
	def __init__(self):
		self.command = POP3Command.QUIT

class POP3STATCommand(POP3CommandBase):
	#NO ARGS
	def __init__(self):
		self.command = POP3Command.STAT

class POP3LISTCommand(POP3CommandBase):
	#optional argument for the messagenumber
	def __init__(self, messageNo = None):
		self.command = POP3Command.LIST
		self.params  = [messageNo] if messageNo is not None else messageNo

class POP3RETRCommand(POP3CommandBase):
	def __init__(self, messageNo):
		self.command = POP3Command.RETR
		self.params  = [messageNo]

class POP3DELECommand(POP3CommandBase):
	#must have an argument for messagenumber 
	def __init__(self, messageNo):
		self.command = POP3Command.DELE
		self.params  = [messageNo]

class POP3TOPCommand(POP3CommandBase):
	"""
	Command for fetching TOP N lines of message MSG
	TOP MGS N
	"""
	#must have 2 arguments argument for messagenumber and number of lines required 
	def __init__(self, messageNo, numLines):
		self.command = POP3Command.TOP
		self.params  = [messageNo, numLines]

class POP3UIDLCommand(POP3CommandBase):
	#messageno optional
	def __init__(self, messageNo = None):
		self.command = POP3Command.UIDL
		self.params  = [messageNo] if messageNo is not None else messageNo

class POP3NOOPCommand(POP3CommandBase):
	#no args
	def __init__(self):
		self.command = POP3Command.NOOP

class POP3USERCommand(POP3CommandBase):
	#param: username
	def __init__(self, username):
		self.command = POP3Command.USER
		self.params  = [username]

class POP3PASSCommand(POP3CommandBase):
	#nparam: passwd
	def __init__(self, password):
		self.command = POP3Command.PASS
		self.params  = [password]

class POP3APOPCommand(POP3CommandBase):
	#
	def __init__(self, user, digest):
		self.command = POP3Command.APOP
		self.params  = [user, digest]

class POP3RSETCommand(POP3CommandBase):
	#no args
	def __init__(self):
		self.command = POP3Command.RSET


class POP3XXXXCommand(POP3CommandBase):
	"""
	Generic catch-all for all unparsable command
	"""
	def __init__(self):
		self.command   = POP3Command.XXXX
		self.raw_data  = None

	def toBytes(self):
		return self.raw_data

class POP3Response():
	"""
	The only way to tell if a multi-line response is expected is by the command issued
	"""
	def __init__(self, code = None, params = None, isMultiline = False):
		self.code   = code
		self.params = params
		self.encoding = 'ascii'

		#if self.code is not None:
		#	self.construct(self.code, self.params)

	def parse(self, buff):
		"""
		BE AWARE: THERE CAN BE MULTI-LINE MESSAGES. This method expects a buffer where all multi-line data is already present
		and will crash if not!
		This is not tested.
		"""

		if isMultiline:
			self.params = []
			while True:
				temp = buff.readline()[:-2].decode(self.encoding)
				if self.code is not None:
					if temp == '.':
						break
					else:
						self.params.append(temp)
				else:
					self.code = POP3ResponseStatus[temp]
		else:
			temp = buff.readline()[:-2].decode(self.encoding)
			marker = temp.find(' ')
			if marker == -1:
				raise Exception('POP3 Response parsing error')
			self.code   = POP3ResponseStatus[temp[:marker]]
			self.params = [temp[marker+1:]]

	def toBytes(self):
		if self.params is None:
			return self.code.value.encode(self.encoding) + b'\r\n'
		elif len(self.params) == 1:
			return self.code.value.encode(self.encoding) + b' ' + self.params[0].encode(self.encoding) + b'\r\n'
		else:
			return self.code.value.encode(self.encoding) + b' ' + self.params[0].encode(self.encoding) + b'\r\n' + b'\r\n'.join(param.encode(self.encoding) for param in self.params[1:]) + b'.\r\n'

	def __repr__(self):
		t  = '== POP3 Response ==\r\n' 
		t += 'STATUS: %s\r\n' % self.code.name
		t += 'ARGS  : %s\r\n' % ' '.join(self.params)
		return t