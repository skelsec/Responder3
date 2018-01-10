import io
import enum

class POP3State(enum.Enum):
	AUTHORIZATION = enum.auto()
	TRANSACTION   = enum.auto()
	UPDATE        = enum.auto()

class POP3ResponseStatus(enum.Enum):
	OK  = '+OK'
	ERR = '-ERR'

class POP3Keyword(enum.Enum):
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

class POP3Command():
	def __init__(self, buff = None):
		self.command = None
		self.args    = None

		if buff is not None:
			self.parse(buff)

	def parse(self,buff):
		temp = buff.readline().decode('ascii').split(' ')
		self.command = POP3Keyword[temp[0]]
		self.args    = temp[1:]

	def construct(self, command, args = None):
		self.command = command
		if isinstance(args, str):
			self.args = [args]
		else:
			self.args = args

	def toBytes(self):
		#TODO multiline messages
		if self.args != []:
			return self.command.name.encode('ascii') + b' '+ b' '.join([arg.encode('ascii') for arg in self.args]) + b'\r\n'
		else:
			return self.command.name.encode('ascii') + b'\r\n'

	def __repr__(self):
		t  = '== POP3 Response ==\r\n' 
		t += 'Command : %s\r\n' % self.command.name
		t += 'ARGS    : %s\r\n' % ''.join(self.args)
		return t

class POP3Response():
	def __init__(self, buff = None):
		self.status = None
		self.args   = None

		if buff is not None:
			self.parse(buff)

	def parse(self,buff):
		self.status = POP3ResponseStatus(buff.read(3).decode('ascii'))
		buff.read(1) #this is for the space
		self.args   = buff.readline()[:-2].decode('ascii')
		while True:
			temp = buff.read(1).decode('ascii')
			if temp != '.':
				buff.seek(-1, io.SEEK_CUR)
				break
			else:
				self.args += buff.readline()[:-2].decode('ascii')

	def toBytes(self):
		#TODO multiline messages
		return self.status.value.encode('ascii') + b' ' + self.args.encode('ascii') + b'\r\n'

	def construct(self, status, args):
		self.status = status
		self.args   = args

	def __repr__(self):
		t  = '== POP3 Response ==\r\n' 
		t += 'STATUS: %s\r\n' % self.status.name
		t += 'ARGS  : %s\r\n' % self.args
		return t


