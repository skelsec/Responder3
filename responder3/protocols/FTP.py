#https://tools.ietf.org/html/rfc959
import io
import enum
import asyncio
import traceback

from responder3.core.logging.log_objects import Credential
from responder3.core.commons import read_element
from responder3.core.asyncio_helpers import *

class FTPState(enum.Enum):
	AUTHORIZATION = enum.auto()
	AUTHENTICATED   = enum.auto()

class FTPCommand(enum.Enum):
	USER = enum.auto()
	PASS = enum.auto()
	ACCT = enum.auto()
	CWD  = enum.auto()
	CDUP = enum.auto()
	SMNT = enum.auto()
	QUIT = enum.auto()
	REIN = enum.auto()
	PORT = enum.auto()
	PASV = enum.auto()
	TYPE = enum.auto()
	STRU = enum.auto()
	MODE = enum.auto()
	RETR = enum.auto()
	STOR = enum.auto()
	STOU = enum.auto()
	APPE = enum.auto()
	ALLO = enum.auto()
	REST = enum.auto()
	RNFR = enum.auto()
	RNTO = enum.auto()
	ABOR = enum.auto()
	DELE = enum.auto()
	RMD  = enum.auto()
	MKD  = enum.auto()
	PWD  = enum.auto()
	LIST = enum.auto()
	NLST = enum.auto()
	SITE = enum.auto()
	SYST = enum.auto()
	STAT = enum.auto()
	HELP = enum.auto()
	NOOP = enum.auto()
	AUTH = enum.auto()
	NLIST= enum.auto()
	FEAT = enum.auto()
	EPSV = enum.auto()
	SIZE = enum.auto()
	XXX = enum.auto()

FTPReplyCode = {
	'110' : "Restart marker reply.",
	'120' : "Service ready in nnn minutes.",
	'125' : "Data connection already open; transfer starting.",
	'150' : "File status okay; about to open data connection.",
	'200' : "Command okay.",
	'202' : "Command not implemented, superfluous at this site.",
	'211' : "System status, or system help reply.",
	'212' : "Directory status.",
	'213' : "File status.",
	'214' : "Help message.", #On how to use the server or the meaning of a particular non-standard command.  This reply is useful only to the human user.
	'215' : "NAME system type.",  # Where NAME is an official system name from the list in the Assigned Numbers document.
	'220' : "Service ready for new user.", 
	'221' : "Service closing control connection.",   #Logged out if appropriate.
	'225' : "Data connection open; no transfer in progress.",   
	'226' : "Closing data connection.",   #Requested file action successful (for example, file transfer or file abort). 
	'227' : "Entering Passive Mode",  #(h1,h2,h3,h4,p1,p2).
	'230' : "User logged in, proceed.",  
	'250' : "Requested file action okay, completed.",  
	'257' : "\"PATHNAME\" created.",
	'331' : "User name okay, need password.",
	'332' : "Need account for login.",
	'350' : "Requested file action pending further information.", 
	'421' : "Service not available, closing control connection.", #This may be a reply to any command if the service knows it must shut down.
	'425' : "Can't open data connection.",
	'426' : "Connection closed; transfer aborted.", 
	'450' : "Requested file action not taken.", #File unavailable (e.g., file busy).
	'451' : "Requested action aborted: local error in processing.", 
	'452' : "Requested action not taken.", #Insufficient storage space in system.
	'500' : "Syntax error, command unrecognized.",  #This may include errors such as command line too long.
	'501' : "Syntax error in parameters or arguments.",
	'502' : "Command not implemented.",
	'503' : "Bad sequence of commands.", 
	'504' : "Command not implemented for that parameter.",
	'522' : "Protocol not implemented",
	'530' : "Not logged in.",
	'532' : "Need account for storing files.",
	'550' : "Requested action not taken.",  #File unavailable (e.g., file not found, no access).
	'551' : "Requested action aborted: page type unknown.", 
	'552' : "Requested file action aborted.",  #Exceeded storage allocation (for current directory or dataset).
	'553' : "Requested action not taken." #File name not allowed.
}


class FTPCommandParser:
	def __init__(self, strict = False, encoding = 'ascii'):
		self.strict      = strict
		self.encoding    = encoding

	async def from_streamreader(self, reader, timeout = 60):
		cmd = await readline_or_exc(reader, timeout=timeout)
		return self.from_bytes(cmd)

	def from_bytes(self, bbuff):
		return self.from_buffer(io.BytesIO(bbuff))

	def from_buffer(self, buff):
		line = buff.readline()
		try:
			command, *params = line.strip().decode(self.encoding).split(' ')
			if command in FTPCommand.__members__:
				return FTPCMD[FTPCommand[command]].from_bytes(line)
			else:
				return FTPXXXCmd.from_bytes(line)

		except Exception as e:
			traceback.print_exc()
			return FTPXXXCmd.from_bytes(line)


class FTPUSERCmd:
	def __init__(self, encoding = 'ascii'):
		self.encoding = encoding
		self.command  = FTPCommand.USER
		self.username = None

	@staticmethod
	def from_buffer(buff, encoding='ascii'):
		return FTPUSERCmd.from_bytes(buff.readline(), encoding)

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = FTPUSERCmd()
		t, bbuff = read_element(bbuff)
		cmd.command = FTPCommand[t]
		cmd.username, bbuff = read_element(bbuff, toend=True)
		return cmd

	@staticmethod
	def construct(username):
		cmd = FTPUSERCmd()
		cmd.username = username
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % (self.command.value, self.username)).encode(self.encoding)

	def __repr__(self):
		t = '== FTP %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'Username    : %s\r\n' % self.username
		return t


class FTPPASSCmd:
	def __init__(self, encoding = 'ascii'):
		self.encoding = encoding
		self.command  = FTPCommand.USER
		self.password = None

	@staticmethod
	def from_buffer(buff, encoding='ascii'):
		return FTPPASSCmd.from_bytes(buff.readline(), encoding)

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = FTPPASSCmd()
		t, bbuff = read_element(bbuff)
		cmd.command = FTPCommand[t]
		cmd.password, bbuff = read_element(bbuff, toend=True)
		return cmd

	@staticmethod
	def construct(username):
		cmd = FTPPASSCmd()
		cmd.username = username
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % (self.command.value, self.password)).encode(self.encoding)

	def __repr__(self):
		t = '== FTP %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'Password: %s\r\n' % self.password
		return t


class FTPXXXCmd:
	def __init__(self, encoding = 'ascii'):
		self.encoding = encoding
		self.command  = FTPCommand.XXX
		self.data = None

	@staticmethod
	def from_buffer(buff, encoding='ascii'):
		return FTPXXXCmd.from_bytes(buff.readline(), encoding)

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		cmd = FTPXXXCmd()
		cmd.data = bbuff.decode(encoding).strip()
		return cmd

	def to_bytes(self):
		return ('%s\r\n' % self.data).encode(self.encoding)

	def __repr__(self):
		t = '== FTP %s Command ==\r\n' % self.command.name
		t += 'DATA : %s\r\n' % self.data
		return t


class FTPReply():
	def __init__(self, code, msg = None):
		self.encoding = 'ascii'
		self.code = str(code)
		self.msg  = None
		if msg is None:
			self.msg  = [FTPReplyCode[self.code]]
		elif isinstance(msg, str):
			self.msg  = [msg]
		elif isinstance(msg, list):
			self.msg  = msg
		else:
			raise Exception('Invalid msg type')

	def to_bytes(self):
		if len(self.msg) == 1:
			return b'%s %s\r\n' % (self.code.encode(self.encoding), self.msg[0].encode(self.encoding))
		elif len(self.msg) == 2:
			temp  = b'%s-%s' % (self.code.encode(self.encoding) , self.msg[0].encode(self.encoding))
			return temp + b'%s %s' % (self.code.encode(self.encoding) , self.msg[1].encode(self.encoding))
		else:
			temp  = b'%s-%s' % (self.code.encode(self.encoding) , self.msg[0].encode(self.encoding))
			temp += b'\r\n'.join(['', (m.encode(self.encoding) for m in self.msg[1:-1] )])
			return temp + b'%s %s' % (self.code.encode(self.encoding) , self.msg[-1].encode(self.encoding))


class FTPAuthMethod(enum.Enum):
	PLAIN = enum.auto()


class FTPAuthStatus(enum.Enum):
	OK = enum.auto()
	NO = enum.auto()
	MORE_DATA_NEEDED = enum.auto()


class FTPAuthHandler:
	def __init__(self, authtype = FTPAuthMethod.PLAIN, creds=None):
		if authtype == FTPAuthMethod.PLAIN:
			self.authahndler = FTPPlainAuth(creds)
		else:
			raise NotImplementedError

	def do_AUTH(self, ftpcmd, salt = None):
		return self.authahndler.update_creds(ftpcmd)


class FTPPlainAuth:
	def __init__(self, creds):
		self.creds = creds
		self.username = None
		self.password = None

	def update_creds(self, ftpcmd):
		if ftpcmd.command == FTPCommand.USER:
			self.username = ftpcmd.username

		elif ftpcmd.command == FTPCommand.PASS:
			self.password = ftpcmd.password

		else:
			raise Exception('Wrong command for authentication!')

		if self.username is not None and self.password is not None:
			return self.verify_creds()

		else:
			return FTPAuthStatus.MORE_DATA_NEEDED, None

	def verify_creds(self):
		c = FTPPlainCred(self.username, self.password)
		if self.creds is None:
			return FTPAuthStatus.OK, c.to_credential()
		else:
			if c.username in self.creds:
				if self.creds[c.username] == c.password:
					return FTPAuthStatus.OK, c.to_credential()

			else:
				return FTPAuthStatus.NO, c.to_credential()

		return FTPAuthStatus.NO, c.to_credential()


class FTPPlainCred:
	def __init__(self, username, password):
		self.username = username
		self.password = password

	def to_credential(self):
		return Credential('PLAIN',
						  username=self.username,
						  password=self.password,
						  fullhash='%s:%s' % (self.username, self.password)
						  )

FTPCMD = {
	FTPCommand.USER: FTPUSERCmd,
	FTPCommand.PASS: FTPPASSCmd,
	#FTPCommand.QUIT: FTPQUITCmd,
}
