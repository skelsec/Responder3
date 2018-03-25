# https://tools.ietf.org/html/rfc5321
# https://stackoverflow.com/questions/8022530/python-check-for-valid-email-address
import re
import io
import enum
import asyncio
import ipaddress

from responder3.core.commons import read_element, readline_or_exc, Credential

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

	@asyncio.coroutine
	def from_streamreader(self, reader):
		buff = yield from readline_or_exc(reader, timeout=self.timeout)
		command, *params = buff.strip().decode(self.encoding).upper().split(' ')
		if command in SMTPCommand.__members__:
			if SMTPCommand[command] in SMTPMultilineCMD:
				while True:
					temp = yield from readline_or_exc(reader, timeout=self.timeout)
					buff += temp
					if temp == b'.\r\n':
						break

		return self.from_bytes(buff)

	def from_bytes(self, bbuff):
		return self.from_buffer(io.BytesIO(bbuff))

	def from_buffer(self, buff):
		line = buff.readline()
		try:
			command, *params = line.strip().decode(self.encoding).upper().split(' ')
			if command in SMTPCommand.__members__:
				return SMTPCMD[SMTPCommand[command]].from_bytes(line)
			else:
				return SMTPXXXXCmd.from_bytes(line)
		except Exception as e:
			print(str(e))
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
		cmd.command = SMTPHELOCmd[t]
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
		cmd.command = SMTPHELOCmd[t]
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
		cmd.command = SMTPHELOCmd[t]
		t, bbuff = read_element(bbuff, toend=True)
		cmd.emailaddress = t[1:-1]
		if bbuff != '':
			cmd.params = bbuff
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
		cmd.command = SMTPHELOCmd[t]
		t, bbuff = read_element(bbuff, toend=True)
		cmd.emailaddress = t[1:-1]
		if bbuff != '':
			cmd.params = bbuff
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
"""
class SMTPCommandParser():
	def __init__(self, strict = False, encoding = 'ascii'):
		self.smtpcommand = None
		self.strict      = strict
		self.encoding    = encoding

	def parse(self, buff):
		raw = buff.readline()
		try:
			temp = raw.decode(self.encoding).strip().split(' ')
			if temp[0].upper() in SMTPCommand.__members__:
				command = SMTPCommand[temp[0].upper()]
			elif not self.strict:
				command = SMTPCommand.XXXX
			else:
				raise Exception('SMTP command parsing error! Command unknown')

			if command == SMTPCommand.HELO or command == SMTPCommand.EHLO:
				self.smtpcommand = SMTPHELOorEHLOCommand()
				try:
					self.smtpcommand.address = ipaddress.ip_address(DomainorAddress)
				except:
					pass
				else:
					self.smtpcommand.domain = domain

			elif command == SMTPCommand.MAIL:
				if temp[1].split(':')[0] != 'FROM':
					raise Exception('MAIL command error!')

				self.smtpcommand = SMTPMAILCommand()
				rawEmail = temp[1].split(':')[1]
				if rawEmail[0] == '<':
					emailAddress = rawEmail[1:-1]

				else:
					marker = rawEmail[0].find('<')
					if marker == -1:
						raise Exception('email not found')
					else:
						emailAddress = rawEmail[marker+1:-1]

				if checkEmailAddress(emailAddress):
					self.smtpcommand.emailFrom = emailAddress

			elif command == SMTPCommand.RCPT:
				if temp[1].split(':')[0] != 'TO':
					raise Exception('RCPT command error!')

				self.smtpcommand = SMTPRCPTCommand()
				rawEmail = temp[1].split(':')[1]
				if rawEmail[0] == '<':
					rawEmail = rawEmail[1:-1]

				#TODO: postmaster stuff
				#if rawEmail == 'Postmaster' or :
				#
				#TODO [SP Rcpt-parameters]
				#TODO relaying address parsing


				if rawEmail.find(',') == -1:
					self.smtpcommand.emailTo = [rawEmail]

				else:
					self.smtpcommand.emailTo = []
					for email in rawEmail.split(','):
						if checkEmailAddress(email):
							self.smtpcommand.emailTo.append(email)

			elif command == SMTPCommand.DATA:
				#his is a two-step command!
				self.smtpcommand = SMTPDATACommand()

			elif command == SMTPCommand.RSET:
				self.smtpcommand = SMTPRSETCommand()

			elif command == SMTPCommand.VRFY:
				self.smtpcommand = SMTPVRFYCommand()
				self.smtpcommand.data = temp[1]

			elif command == SMTPCommand.EXPN:
				self.smtpcommand = SMTPEXPNCommand()
				self.smtpcommand.data = temp[1]

			elif command == SMTPCommand.HELP:
				self.smtpcommand = SMTPHELPCommand()
				if len(temp) > 1:
					self.smtpcommand.data = temp[1]

			elif command == SMTPCommand.NOOP:
				self.smtpcommand = SMTPNOOPCommand()
				if len(temp) > 1:
					self.smtpcommand.data = temp[1]

			elif command == SMTPCommand.QUIT:
				self.smtpcommand = SMTPQUITCommand()

			elif command == SMTPCommand.AUTH:
				self.smtpcommand = SMTPAUTHCommand()
				self.smtpcommand.mechanism = temp[1]
				if len(temp) > 2:
					self.smtpcommand.initresp = temp[2]

			elif command == SMTPCommand.XXXX:
				self.smtpcommand.data = raw

		except Exception as e:
			print(str(e))
			self.smtpcommand = SMTPXXXXCommand()
			self.smtpcommand.raw_data = raw

		return self.smtpcommand
"""

class SMTPReplyParser:
	def __init__(self, buff):
		self.smtpreply = None

		if buff is not None:
			self.parse(buff)

	def parse(self, buff, rec = False):
		temp = buff.readline()[:-2].decode('ascii')
		reply = int(temp[:4],10)
		if reply not in SMTPReplyCode:
			raise Exception('Unknown REPLY code!')
		
		if rec:
			if reply != self.smtpreply:
				raise Exception('Multiline message format error!')
			self.parameter.append(temp[5:])

		else:
			self.smtpreply = SMTPReply()
			self.smtpreply.code = reply
			self.parameter.append(temp[5:])
		
		if temp[4] == '-':
			self.parse(buff, rec = True)
		elif temp[4] == ' ':
			if rec:
				return
			return self.smtpreply
		else:
			raise Exception('Multiline message format error!')


class SMTPReply:
	def __init__(self, code = None, params = None):
		self.code      = code
		self.parameter = params #is list

		if self.code is not None:
			self.construct(self.code, self.parameter)

	def construct(self, code, data = None):
		self.code = code
		if data is None:
			self.parameter = [SMTPReplyCode[code]]
		elif isinstance(data,str):
			self.parameter = [data]
		elif isinstance(data,list):
			self.parameter = data
		else:
			raise Exception('Unknown data for SMTP reply!')

	def toBytes(self):
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
		self.raw_data  = None

	def construct(self):
		"""
		this should not be used for constructing
		"""
		pass

	def toBytes(self):
		return self.raw_data.encode('ascii')


class SMTPAUTHCmd:
	def __init__(self):
		self.command   = SMTPCommand.AUTH
		self.mechanism = None
		self.initresp  = None

	def construct(self, mechanism, initresp = None):
		self.mechanism = mechanism
		self.initresp  = None

	def toBytes(self):
		if self.initresp is not None:
			return b' '.join([self.command.name.encode('ascii'), self.mechanism.encode('ascii'), self.initresp.encode('ascii')]) +b'\r\n'
		else:
			return b' '.join([self.command.name.encode('ascii'), self.mechanism.encode('ascii')]) +b'\r\n'


class SMTPQUITCmd:
	def __init__(self):
		self.command   = SMTPCommand.NOOP

	def construct(self, data):
		pass

	def toBytes(self):
		return self.command.name.encode('ascii') +b'\r\n'


class SMTPNOOPCmd:
	def __init__(self):
		self.command   = SMTPCommand.NOOP
		self.data      = None

	def construct(self, data):
		self.data      = data

	def toBytes(self):
		if self.data is not None:
			return self.command.name.encode('ascii') + b' ' +self.data.encode('ascii') +b'\r\n'
		else:
			return self.command.name.encode('ascii') + b'\r\n'


class SMTPHELPCmd:
	def __init__(self):
		self.command   = SMTPCommand.HELP
		self.data      = None

	def construct(self, data):
		self.data      = data

	def toBytes(self):
		if self.data is not None:
			return self.command.name.encode('ascii') + b' ' +self.data.encode('ascii') +b'\r\n'
		else:
			return self.command.name.encode('ascii') +b'\r\n'


class SMTPEXPNCmd:
	def __init__(self):
		self.command   = SMTPCommand.VRFY
		self.data      = None

	def construct(self, data):
		self.data      = data

	def toBytes(self):
		return self.command.name.encode('ascii') + b' ' +self.data.encode('ascii') +b'\r\n'


class SMTPVRFYCmd:
	def __init__(self):
		self.command   = SMTPCommand.VRFY
		self.data      = None

	def construct(self, data):
		self.data      = data

	def toBytes(self):
		return self.command.name.encode('ascii') + b' ' +self.data.encode('ascii') +b'\r\n'


class SMTPRSETCmd:
	def __init__(self):
		self.command   = SMTPCommand.RSET

	def construct(self):
		pass

	def toBytes(self):
		return self.command + b'\r\n'


class SMTPDATACmd:
	def __init__(self):
		self.command   = SMTPCommand.DATA
		self.emailData = None #will be a list!

	def construct(self, emaildata):
		self.emailData = emaildata

	def toBytes(self):
		return [self.command.name.encode('ascii') + b'\r\n', self.emailData.replace('\r\n','\n').encode('ascii') + b'\r\n.\r\n']


class SMTPRCPTCmd:
	def __init__(self):
		self.command = SMTPCommand.RCPT
		self.emailTo = None #will be a list!

	def construct(self, emailAddressList, check = True):
		if isintance(emailAddressList, str):
			self.emailTo = [emailAddressList]
		if isintance(emailAddressList, list):
			self.emailTo = emailAddressList

		if check:
			for emailAddress in self.emailTo:
				if not EMAIL_REGEX.match(emailAddress):
					raise Exception('emailAddress not an email address!')

	def toBytes(self):
		return self.command.name.encode('ascii') + b' <' + str(self.emailFrom).encode('ascii') + b'>\r\n'


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