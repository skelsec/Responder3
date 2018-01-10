
#https://tools.ietf.org/html/rfc3501
import io
import enum

class IMAPState(enum.Enum):
	NOTAUTHENTICATED = enum.auto()
	AUTHENTICATED    = enum.auto()
	SELECTED         = enum.auto()
	LOGOUT           = enum.auto()

class IMAPServerResponse(enum.Enum):
	OK         = enum.auto()
	NO         = enum.auto()
	BAD        = enum.auto()
	PREAUTH    = enum.auto()
	BYE        = enum.auto()
	CAPABILITY = enum.auto()
	LIST       = enum.auto()
	LSUB       = enum.auto()
	STATUS     = enum.auto()
	SEARCH     = enum.auto()
	FLAGS      = enum.auto()
	EXISTS     = enum.auto()
	RECENT     = enum.auto()
	EXPUNGE    = enum.auto()
	FETCH      = enum.auto()

class IMAPClientCommand(enum.Enum):
	CAPABILITY   = enum.auto()
	NOOP         = enum.auto()
	LOGOUT       = enum.auto()
	STARTTLS     = enum.auto()
	AUTHENTICATE = enum.auto()
	LOGIN        = enum.auto()
	SELECT       = enum.auto()
	EXAMINE      = enum.auto()
	CREATE       = enum.auto()
	DELETE       = enum.auto()
	RENAME       = enum.auto()
	SUBSCRIBE    = enum.auto()
	UNSUBSCRIBE  = enum.auto()
	LIST         = enum.auto()
	LSUB         = enum.auto()
	STATUS       = enum.auto()
	APPEND       = enum.auto()
	Client       = enum.auto()
	CHECK        = enum.auto()
	CLOSE        = enum.auto()
	EXPUNGE      = enum.auto()
	SEARCH       = enum.auto()
	FETCH        = enum.auto()
	STORE        = enum.auto()
	COPY         = enum.auto()
	UID          = enum.auto()

IMAPResponseGroup = {
	'STATUS' : [IMAPServerResponse.OK,
				IMAPServerResponse.NO,
				IMAPServerResponse.BAD,
				IMAPServerResponse.PREAUTH,
	],
	
	'MBSTATUS':[ IMAPServerResponse.CAPABILITY,
				IMAPServerResponse.LIST,
				IMAPServerResponse.LSUB,
				IMAPServerResponse.STATUS,
				IMAPServerResponse.SEARCH,
				IMAPServerResponse.FLAGS,
	],

	'MBSIZE':[  IMAPServerResponse.EXISTS,
				IMAPServerResponse.RECENT,
	],
	'MSGSTAT':[  IMAPServerResponse.EXPUNGE,
				 IMAPServerResponse.FETCH,
	],
	#'CMDCONTRQ':[
	#],
}


class IMAPCommand():
	def __init__(self, buff = None):
		self.tag     = None
		self.command = None
		self.args    = None

		if buff is not None:
			self.parse(buff)

	def parse(self,buff):
		temp = buff.readline()[:-2].decode('utf-7').split(' ')
		self.tag     = temp[0]
		self.command = IMAPClientCommand[temp[1]]
		self.args    = temp[2:]

	def construct(self, tag, command, args = None):
		self.tag     = tag
		self.command = command
		if isinstance(args, str):
			self.args = [args]
		else:
			self.args = args

	def toBytes(self):
		#TODO multiline messages
		if self.args != []:
			return b' '.join([self.tag.encode('utf-7'),self.command.name.encode('utf-7'),b' '.join([arg.encode('utf-7') for arg in self.args])]) + b'\r\n'
		else:
			return b' '.join([self.tag.encode('utf-7'),self.command.name.encode('utf-7')])+ b'\r\n'

	def __repr__(self):
		t  = '== IMAP Response ==\r\n' 
		t += 'Command : %s\r\n' % self.command.name
		t += 'ARGS    : %s\r\n' % ' '.join(self.args)
		return t

class IMAPResponse():
	def __init__(self, buff = None):
		self.tag    = None
		self.status = None
		self.args   = None

		if buff is not None:
			self.parse(buff)

	def parse(self,buff):
		temp = buff.readline()[:-2].decode('utf-7').split(' ')
		self.tag = temp[0]
		self.status = IMAPServerResponse[temp[1]]
		self.args   = temp[2:]
		while True:
			temp = buff.read(1).decode('utf-7')
			if temp != '.':
				buff.seek(-1, io.SEEK_CUR)
				break
			else:
				self.args += buff.readline()[:-2].decode('utf-7')

	def toBytes(self):
		if self.args != []:
			return b' '.join([self.tag.encode('utf-7'), self.status.name.encode('utf-7'),  b' '.join([arg.encode('utf-7') for arg in self.args])]) + b'\r\n'
		else:
			return b' '.join([self.tag.encode('utf-7'), self.status.name.encode('utf-7')]) + b'\r\n'

	def construct(self, tag, status, args):
		self.tag    = tag
		self.status = status
		if isinstance(args, str):
			self.args = [args]
		else:
			self.args = args

	def __repr__(self):
		t  = '== IMAP Response ==\r\n' 
		t += 'STATUS: %s\r\n' % self.status.name
		t += 'ARGS  : %s\r\n' % self.args
		return t


