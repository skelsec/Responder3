# https://tools.ietf.org/html/rfc5321
# https://stackoverflow.com/questions/8022530/python-check-for-valid-email-address
import re
import io
import enum
import asyncio
import ipaddress
import traceback
from base64 import b64decode, b64encode

from responder3.core.commons import read_element, Credential
from responder3.core.asyncio_helpers import *

EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")


class SMTPServerState(enum.Enum):
	START           = enum.auto()
	DATAINCOMING    = enum.auto()
	DATAFINISHED    = enum.auto()
	NOTAUTHETICATED = enum.auto()
	AUTHSTARTED     = enum.auto()
	AUTHENTICATED   = enum.auto()
	MAIL            = enum.auto()


SMTPReplyCode = {
	211: 'System status, or system help reply',
	214: 'Help message', #(Information on how to use the receiver or the meaning of a particular non-standard command; this reply is useful only to the human user)
	220: '{domain} Service ready',
	221: '{domain} Service closing transmission channel',
	235: 'Authentication Succeeded',
	250: 'Requested mail action okay, completed',
	251: 'User not local; will forward to <forward-path>', #(See Section 3.4)
	252: 'Cannot VRFY user, but will accept message and attempt delivery', #(See Section 3.5.3)
	334: '',
	354: 'Start mail input; end with <CRLF>.<CRLF>',
	421: '{domain} Service not available, closing transmission channel', #(This may be a reply to any command if the service knows it must shut down)
	432: 'A password transition is needed',
	450: 'Requested mail action not taken: mailbox unavailable', #(e.g., mailbox busy or temporarily blocked for policy reasons)
	451: 'Requested action aborted: local error in processing',
	452: 'Requested action not taken: insufficient system storage',
	454: 'Temporary authentication failure',
	455: 'Server unable to accommodate parameters',
	500: 'Syntax error, command unrecognized', #(This may include errors such as command line too long)
	501: 'Syntax error in parameters or arguments',
	502: 'Command not implemented', #(see Section 4.2.4)
	503: 'Bad sequence of commands',
	504: 'Command parameter not implemented',
	530: 'Authentication required',
	534: 'Authentication mechanism is too weak',
	535: 'Authentication credentials invalid',
	538: 'Encryption required for requested authentication  mechanism',
	550: 'Requested action not taken: mailbox unavailable', #(e.g., mailbox not found, no access, or command rejected for policy reasons)
	551: 'User not local; please try <forward-path>', #(See Section 3.4)
	552: 'Requested mail action aborted: exceeded storage allocation',
	553: 'Requested action not taken: mailbox name not allowed #(e.g., mailbox syntax incorrect)',
	554: 'Transaction failed', #(Or, in the case of a connection-opening response, "No SMTP service here")
	555: 'MAIL FROM/RCPT TO parameters not recognized or not implemented',
	666: 'A thousand nights we\'ve been calling your name Close your eyes but I won\'t go away We\'re there for you'
}


class SMTPCommand(enum.Enum):
	HELO = enum.auto()
	EHLO = enum.auto()
	MAIL = enum.auto()
	RCPT = enum.auto()
	DATA = enum.auto()
	RSET = enum.auto()
	VRFY = enum.auto()
	EXPN = enum.auto()
	HELP = enum.auto()
	NOOP = enum.auto()
	QUIT = enum.auto()
	AUTH = enum.auto()
	XXXX = enum.auto() #this is a shortcut for unparsable input


SMTPMultilineCMD = [
	SMTPCommand.DATA,
]


class SMTPCommandParser:
	def __init__(self, encoding='ascii', timeout = 60):
		self.encoding = encoding
		self.timeout = timeout
		self.is_mulitline = False
		self.multiline_cmd = None
		self.multiline_buffer = None

	async def from_streamreader(self, reader):
		if self.is_mulitline:
			while True:
				temp = await readline_or_exc(reader, timeout=self.timeout)
				self.multiline_buffer += temp
				if temp == b'.\r\n':
					self.is_mulitline = False
					cmd = self.from_bytes(self.multiline_buffer)
					self.multiline_buffer = None
					return cmd

		buff = await readline_or_exc(reader, timeout=self.timeout)

		command, *params = buff.strip().decode(self.encoding).upper().split(' ')
		if command in SMTPCommand.__members__:
			if SMTPCommand[command] in SMTPMultilineCMD:
				self.is_mulitline = True
				self.multiline_buffer = buff
				return SMTPCMD[SMTPCommand[command]].from_bytes(None)

		return self.from_bytes(buff)

	def from_bytes(self, bbuff):
		return self.from_buffer(io.BytesIO(bbuff))

	def from_buffer(self, buff):
		pos = buff.tell()
		line = buff.readline()
		try:
			command, *params = line.strip().decode(self.encoding).upper().split(' ')
			if command in SMTPCommand.__members__:
				if SMTPCommand[command] in SMTPMultilineCMD:
					buff.seek(pos)
					return SMTPCMD[SMTPCommand[command]].from_bytes(buff.read())
				else:
					return SMTPCMD[SMTPCommand[command]].from_bytes(line)
			else:
				return SMTPXXXXCmd.from_bytes(line)

		except Exception as e:
			traceback.print_exc()
			return SMTPXXXXCmd.from_bytes(line)


# class SMTPHELOorEHLOCommand:
class SMTPHELOCmd:
	def __init__(self, encoding = 'ascii'):
		self.encoding = encoding
		self.command = SMTPCommand.HELO
		self.domain = None

	@staticmethod
	def from_buffer(buff, encoding='ascii'):
		return SMTPHELOCmd.from_bytes(buff.readline(), encoding)

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPHELOCmd()
		t, bbuff = read_element(bbuff, toend=True)
		cmd.command = SMTPCommand[t.upper()]
		cmd.msgno, bbuff = read_element(bbuff, toend=True)
		return cmd

	@staticmethod
	def construct(domain):
		cmd = SMTPHELOCmd()
		cmd.domain = domain
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % (self.command.value, self.domain)).encode(self.encoding)

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'Domain  : %s\r\n' % self.domain
		return t


class SMTPEHLOCmd:
	def __init__(self, encoding= 'ascii'):
		self.encoding = encoding
		self.command = SMTPCommand.EHLO
		self.domain = None

	@staticmethod
	def from_buffer(buff, encoding='ascii'):
		return SMTPEHLOCmd.from_bytes(buff.readline(), encoding)

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPEHLOCmd()
		t, bbuff = read_element(bbuff, toend=True)
		cmd.command = SMTPCommand[t.upper()]
		cmd.msgno, bbuff = read_element(bbuff, toend=True)
		return cmd

	@staticmethod
	def construct(domain):
		cmd = SMTPEHLOCmd()
		cmd.domain = domain
		return cmd

	def to_bytes(self):
		return ('%s %s\r\n' % (self.command.value, self.domain)).encode(self.encoding)

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'Domain  : %s\r\n' % self.domain
		return t


class SMTPMAILCmd:
	def __init__(self, encoding= 'ascii'):
		self.encoding = encoding
		self.command = SMTPCommand.MAIL
		self.emailaddress = None
		self.params = None

	@staticmethod
	def from_buffer(buff, encoding='ascii'):
		return SMTPMAILCmd.from_bytes(buff.readline(), encoding)

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPMAILCmd()
		t, bbuff = read_element(bbuff)
		cmd.command = SMTPCommand[t.upper()]
		t, bbuff = read_element(bbuff, marker=':')
		temp_email = bbuff.strip()
		if temp_email[0] == '<':
			temp_email = temp_email[1:]
			cmd.emailaddress, bbuff = read_element(temp_email, marker='>', toend= True)

		else:
			# this case means the email address was defined in an old format, using spaces
			cmd.emailaddress, bbuff = read_element(temp_email, toend= True)

		if bbuff != '':
			cmd.params = bbuff.split(' ')

		return cmd

	@staticmethod
	def construct(emailaddress, params = None):
		cmd = SMTPMAILCmd()
		cmd.emailaddress = emailaddress
		cmd.params = params
		return cmd

	def to_bytes(self):
		if self.params is not None:
			return ('%s %s %s\r\n' % (self.command.value, self.emailaddress, self.params)).encode(self.encoding)
		else:
			return ('%s %s\r\n' % (self.command.value, self.emailaddress)).encode(self.encoding)

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'emailaddress  : %s\r\n' % self.emailaddress
		t += 'params  : %s\r\n' % self.params
		return t


class SMTPRCPTCmd:
	# TODO: envelope command parsing?
	def __init__(self, encoding= 'ascii'):
		self.encoding = encoding
		self.command = SMTPCommand.RCPT
		self.emailaddress = None
		self.params = None

	@staticmethod
	def from_buffer(buff, encoding='ascii'):
		return SMTPRCPTCmd.from_bytes(buff.readline(), encoding)

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPRCPTCmd()
		t, bbuff = read_element(bbuff)
		cmd.command = SMTPCommand[t.upper()]
		t, bbuff = read_element(bbuff, marker=':')
		temp_email = bbuff.strip()
		if temp_email[0] == '<':
			temp_email = temp_email[1:]
			cmd.emailaddress, bbuff = read_element(temp_email, marker='>', toend=True)

		else:
			# this case means the email address was defined in an old format, using spaces
			cmd.emailaddress, bbuff = read_element(temp_email, toend=True)

		if bbuff != '':
			cmd.params = bbuff.split(' ')

		return cmd

	@staticmethod
	def construct(emailaddress, params = None):
		cmd = SMTPRCPTCmd()
		cmd.emailaddress = emailaddress
		cmd.params = params
		return cmd

	def to_bytes(self):
		if self.params is not None:
			return ('%s %s %s\r\n' % (self.command.value, self.emailaddress, self.params)).encode(self.encoding)
		else:
			return ('%s %s\r\n' % (self.command.value, self.emailaddress)).encode(self.encoding)

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'emailaddress  : %s\r\n' % self.emailaddress
		t += 'params  : %s\r\n' % self.params
		return t


class SMTPResponseParser:
	def __init__(self, encoding='ascii', timeout = 60, multiline_buffer_size_limit = 4096):
		self.encoding = encoding
		self.timeout = timeout
		self.multiline_buffer_size_limit = multiline_buffer_size_limit

	async def from_streamreader(self, reader):
		is_multiline = True
		multiline_buffer = b''

		while True:
			buff = await readline_or_exc(reader, timeout=self.timeout)
			line = buff.strip().decode(self.encoding)
			if line[3] == '-':
				is_multiline = True
				multiline_buffer += buff
				if len(multiline_buffer) > self.multiline_buffer_size_limit:
					raise Exception('Multiline size limit reached!')
				continue

			else:
				if not is_multiline:
					return self.from_bytes(buff)
				else:
					multiline_buffer += buff
					if len(multiline_buffer) > self.multiline_buffer_size_limit:
						raise Exception('Multiline size limit reached!')
					return self.from_bytes(multiline_buffer)
				break

	def from_socket(self, sock):
		buffer = b''
		while True:
			temp = sock.recv(4096)
			if temp == b'':
				break

			buffer += temp
			bsize = len(buffer)
			if bsize > self.multiline_buffer_size_limit:
				raise Exception('Multiline size limit reached!')
			if bsize > 4:
				if buffer[:-1] == b'\n':
					if buffer[3] == b'-':
						continue
					else:
						return self.from_bytes(buffer)
				else:
					continue

	def from_bytes(self, bbuff):
		return self.from_buffer(io.BytesIO(bbuff))

	def from_buffer(self, buff):
		response = None
		lines = buff.readlines()
		for line in lines:
			try:
				temp = line.strip().decode(self.encoding)
				status_code = int(temp[:3], 10)
				if status_code not in SMTPReplyCode:
					raise Exception('Unknown REPLY code!')

				if response is None:
					response = SMTPReply()
					response.code = status_code
					response.parameter.append(temp[4:])
				else:
					if status_code != response.code:
						raise Exception('SMTP Multiline response with mismatching status codes!')

					response.parameter.append(temp[4:])

			except Exception as e:
				raise e

		return response


class SMTPReply:
	def __init__(self):
		self.code      = None
		self.parameter = []

	@staticmethod
	def construct(code, data = None):
		rep = SMTPReply()
		rep.code = code
		if data is None:
			rep.parameter = [SMTPReplyCode[code]]
		elif isinstance(data, str):
			rep.parameter = [data]
		elif isinstance(data, list):
			rep.parameter = data
		else:
			raise Exception('Unknown data for SMTP reply!')
		return rep

	def to_bytes(self):
		"""
		returns a list of bytes
		"""
		if self.parameter is None:
			raise Exception('Empty data for SMTP reply!')
		if len(self.parameter) == 1:
			return str(self.code).encode('ascii') + b' ' + self.parameter[-1].encode('ascii') + b'\r\n'
		else:
			temp = (str(self.code).encode('ascii') + b'-').join([b''] + [param.encode('ascii')+ b'\r\n' for param in self.parameter[:-1]])
			temp += str(self.code).encode('ascii') + b' ' + self.parameter[-1].encode('ascii') + b'\r\n'
			return temp
	

def checkEmailAddress(emailAddress):
	if not EMAIL_REGEX.match(emailAddress):
		raise Exception('Email FROM not an email address!')
	return True


class SMTPXXXXCmd:
	"""
	this is a container for unknown messages
	"""
	def __init__(self):
		self.command   = SMTPCommand.XXXX
		self.data  = None

	def construct(self):
		"""
		this should not be used for constructing
		"""
		pass

	@staticmethod
	def from_bytes(bbuff):
		return SMTPXXXXCmd.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		xxx = SMTPXXXXCmd()
		xxx.data = buff.read()
		return xxx

	def to_bytes(self):
		return self.data.encode('ascii')

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'data      : %s\r\n' % repr(self.data)
		return t


class SMTPAUTHCmd:
	def __init__(self):
		self.command   = SMTPCommand.AUTH
		self.mechanism = None
		self.data  = None

	def construct(self, mechanism, data = None):
		self.mechanism = mechanism
		self.data  = None

	def to_bytes(self):
		if self.data is not None:
			return b' '.join([self.command.name.encode('ascii'), self.mechanism.encode('ascii'), self.data.encode('ascii')]) +b'\r\n'
		else:
			return b' '.join([self.command.name.encode('ascii'), self.mechanism.encode('ascii')]) +b'\r\n'

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPAUTHCmd()
		t, bbuff = read_element(bbuff)
		cmd.command = SMTPCommand[t.upper()]
		cmd.mechanism, bbuff = read_element(bbuff, toend = True)
		if len(bbuff) > 0:
			cmd.data = bbuff
		return cmd

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'mechanism : %s\r\n' % repr(self.mechanism)
		t += 'data      : %s\r\n' % repr(self.data)
		return t


class SMTPQUITCmd:
	def __init__(self):
		self.command   = SMTPCommand.NOOP

	def construct(self):
		pass

	def to_bytes(self):
		return self.command.name.encode('ascii') + b'\r\n'

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPQUITCmd()
		t, bbuff = read_element(bbuff, toend= True)
		cmd.command = SMTPCommand[t.upper()]
		return cmd

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		return t


class SMTPNOOPCmd:
	def __init__(self):
		self.command   = SMTPCommand.NOOP
		self.data      = None

	def construct(self, data):
		self.data      = data

	def to_bytes(self):
		if self.data is not None:
			return self.command.name.encode('ascii') + b' ' + ' '.join(self.data).encode('ascii') + b'\r\n'
		else:
			return self.command.name.encode('ascii') + b'\r\n'

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPNOOPCmd()
		t, bbuff = read_element(bbuff, toend= True)
		cmd.command = SMTPCommand[t.upper()]
		if len(bbuff) > 0:
			cmd.data = bbuff.split(' ')
		return cmd

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'data  : %s\r\n' % repr(self.data)
		return t


class SMTPHELPCmd:
	def __init__(self):
		self.command   = SMTPCommand.HELP
		self.data      = None

	def construct(self, data):
		self.data      = data

	def to_bytes(self):
		if self.data is not None:
			return self.command.name.encode('ascii') + b' ' + ' '.join(self.data).encode('ascii') +b'\r\n'
		else:
			return self.command.name.encode('ascii') +b'\r\n'

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPHELPCmd()
		t, bbuff = read_element(bbuff, toend= True)
		cmd.command = SMTPCommand[t.upper()]
		if len(bbuff) > 0:
			cmd.data = bbuff.split(' ')
		return cmd

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'data  : %s\r\n' % repr(self.data)
		return t


class SMTPEXPNCmd:
	def __init__(self):
		self.command   = SMTPCommand.VRFY
		self.username      = None

	def construct(self, data):
		self.username      = data

	def to_bytes(self):
		return self.command.name.encode('ascii') + b' ' +self.username.encode('ascii') +b'\r\n'

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPEXPNCmd()
		t, bbuff = read_element(bbuff, toend= True)
		cmd.command = SMTPCommand[t.upper()]
		cmd.username = bbuff
		return cmd

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'username  : %s\r\n' % repr(self.username)
		return t


class SMTPVRFYCmd:
	def __init__(self):
		self.command   = SMTPCommand.VRFY
		self.username  = None

	def construct(self, data):
		self.username      = data

	def to_bytes(self):
		return self.command.name.encode('ascii') + b' ' +self.username.encode('ascii') +b'\r\n'

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPVRFYCmd()
		t, bbuff = read_element(bbuff, toend= True)
		cmd.command = SMTPCommand[t.upper()]
		cmd.username = bbuff
		return cmd

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'username  : %s\r\n' % repr(self.username)
		return t



class SMTPRSETCmd:
	def __init__(self):
		self.command   = SMTPCommand.RSET

	def construct(self):
		pass

	def to_bytes(self):
		return self.command + b'\r\n'

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPRSETCmd()
		t, bbuff = read_element(bbuff, toend= True)
		cmd.command = SMTPCommand[t.upper()]
		return cmd

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		return t


class SMTPDATACmd:
	def __init__(self):
		self.command   = SMTPCommand.DATA
		self.emaildata = None

	def construct(self, emaildata):
		self.emaildata = emaildata

	def to_bytes(self):
		return [self.command.name.encode('ascii') + b'\r\n', self.emailData.replace('\r\n','\n').encode('ascii') + b'\r\n.\r\n']

	@staticmethod
	def from_bytes(bbuff, encoding='ascii'):
		if bbuff is None:
			# we return an empty instance, as this command is muliline
			return SMTPDATACmd()
		bbuff = bbuff.decode(encoding).strip()
		cmd = SMTPDATACmd()
		t, bbuff = read_element(bbuff, marker='\n')
		cmd.command = SMTPCommand[t.strip().upper()]
		cmd.emaildata = ''
		for line in bbuff.split('\n'):
			if line.strip() == '.':
				break
			cmd.emaildata += line + '\n'
		return cmd

	def __repr__(self):
		t = '== SMTP %s Command ==\r\n' % self.command.name
		t += 'Command : %s\r\n' % self.command.name
		t += 'emaildata  : %s\r\n' % repr(self.emaildata)
		return t


class SMTPAuthStatus(enum.Enum):
	OK = enum.auto()
	NO = enum.auto()
	MORE_DATA_NEEDED = enum.auto()


class SMTPAuthMethod(enum.Enum):
	PLAIN = enum.auto()
	CRAM_MD5 = enum.auto()


class SMTPPlainAuth:
	def __init__(self, creds):
		self.creds = creds
		self.username = None
		self.password = None

	def update_creds(self, cmd):
		if cmd.command == SMTPCommand.AUTH:
			if cmd.data is not None:
				authdata = b64decode(cmd.data).split(b'\x00')[1:]
				self.username = authdata[0].decode('ascii')
				self.password = authdata[1].decode('ascii')
			else:
				return SMTPAuthStatus.MORE_DATA_NEEDED, None

		else:
			authdata = b64decode(cmd.data).split(b'\x00')[1:]
			self.username = authdata[0].decode('ascii')
			self.password = authdata[1].decode('ascii')

		if self.username is not None and self.password is not None:
			return self.verify_creds()

		else:
			return SMTPAuthStatus.MORE_DATA_NEEDED, None

	def verify_creds(self):
		c = SMTPPlainCred(self.username, self.password)
		if self.creds is None:
			return SMTPAuthStatus.OK, c.toCredential()
		else:
			if c.username in self.creds:
				if self.creds[c.username] == c.password:
					return SMTPAuthStatus.OK, c.toCredential()

			else:
				return SMTPAuthStatus.NO, c.toCredential()

		return SMTPAuthStatus.NO, c.toCredential()


class SMTPPlainCred:
	def __init__(self, username, password):
		self.username = username
		self.password = password

	def toCredential(self):
		return Credential('PLAIN',
						  username=self.username,
						  password=self.password,
						  fullhash='%s:%s' % (self.username, self.password)
						  )


class SMTPAuthHandler:
	def __init__(self, authtype, creds=None, salt = None):
		if authtype == SMTPAuthMethod.PLAIN:
			self.authahndler = SMTPPlainAuth(creds)
		elif authtype == SMTPAuthMethod.CRAM_MD5:
			self.authahndler = SMTPCRAM_MD5Auth(creds, salt)
		else:
			raise NotImplementedError

	def do_AUTH(self, cmd, salt = None):
		return self.authahndler.update_creds(cmd)

SMTPCMD = {
	SMTPCommand.HELO: SMTPHELOCmd,
	SMTPCommand.EHLO: SMTPEHLOCmd,
	SMTPCommand.MAIL: SMTPMAILCmd,
	SMTPCommand.RCPT: SMTPRCPTCmd,
	SMTPCommand.DATA: SMTPDATACmd,
	SMTPCommand.RSET: SMTPRSETCmd,
	SMTPCommand.VRFY: SMTPVRFYCmd,
	SMTPCommand.EXPN: SMTPEXPNCmd,
	SMTPCommand.HELP: SMTPHELPCmd,
	SMTPCommand.NOOP: SMTPNOOPCmd,
	SMTPCommand.QUIT: SMTPQUITCmd,
	SMTPCommand.AUTH: SMTPAUTHCmd,
	SMTPCommand.XXXX: SMTPXXXXCmd,
}