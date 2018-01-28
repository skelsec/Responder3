#https://tools.ietf.org/html/rfc5321
#https://stackoverflow.com/questions/8022530/python-check-for-valid-email-address
import re
import enum
import ipaddress
import base64

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
	211 : 'System status, or system help reply',
	214 : 'Help message', #(Information on how to use the receiver or the meaning of a particular non-standard command; this reply is useful only to the human user)
	220 : '{domain} Service ready',
	221 : '{domain} Service closing transmission channel',
	235 : 'Authentication Succeeded',
	250 : 'Requested mail action okay, completed',
	251 : 'User not local; will forward to <forward-path>', #(See Section 3.4)
	252 : 'Cannot VRFY user, but will accept message and attempt delivery', #(See Section 3.5.3)
	354 : 'Start mail input; end with <CRLF>.<CRLF>',
	421 : '{domain} Service not available, closing transmission channel', #(This may be a reply to any command if the service knows it must shut down)
	432 : 'A password transition is needed',
	450 : 'Requested mail action not taken: mailbox unavailable', #(e.g., mailbox busy or temporarily blocked for policy reasons)
	451 : 'Requested action aborted: local error in processing',
	452 : 'Requested action not taken: insufficient system storage',
	454 : 'Temporary authentication failure',
	455 : 'Server unable to accommodate parameters',
	500 : 'Syntax error, command unrecognized', #(This may include errors such as command line too long)
	501 : 'Syntax error in parameters or arguments',
	502 : 'Command not implemented', #(see Section 4.2.4)
	503 : 'Bad sequence of commands',
	504 : 'Command parameter not implemented',
	530 : 'Authentication required',
	534 : 'Authentication mechanism is too weak',
	535 : 'Authentication credentials invalid',
	538 : 'Encryption required for requested authentication  mechanism',
	550 : 'Requested action not taken: mailbox unavailable', #(e.g., mailbox not found, no access, or command rejected for policy reasons)
	551 : 'User not local; please try <forward-path>', #(See Section 3.4)
	552 : 'Requested mail action aborted: exceeded storage allocation',
	553 : 'Requested action not taken: mailbox name not allowed #(e.g., mailbox syntax incorrect)',
	554 : 'Transaction failed', #(Or, in the case of a connection-opening response, "No SMTP service here")
	555 : 'MAIL FROM/RCPT TO parameters not recognized or not implemented',
	666 : 'A thousand nights we\'ve been calling your name Close your eyes but I won\'t go away We\'re there for you'
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

class SMTPReplyParser():
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


class SMTPReply():
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


class SMTPXXXXCommand():
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

class SMTPAUTHCommand():
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

class SMTPQUITCommand():
	def __init__(self):
		self.command   = SMTPCommand.NOOP

	def construct(self, data):
		pass

	def toBytes(self):
		return self.command.name.encode('ascii') +b'\r\n'

class SMTPNOOPCommand():
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

class SMTPHELPCommand():
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

class SMTPEXPNCommand():
	def __init__(self):
		self.command   = SMTPCommand.VRFY
		self.data      = None

	def construct(self, data):
		self.data      = data

	def toBytes(self):
		return self.command.name.encode('ascii') + b' ' +self.data.encode('ascii') +b'\r\n'

class SMTPVRFYCommand():
	def __init__(self):
		self.command   = SMTPCommand.VRFY
		self.data      = None

	def construct(self, data):
		self.data      = data

	def toBytes(self):
		return self.command.name.encode('ascii') + b' ' +self.data.encode('ascii') +b'\r\n'

class SMTPRSETCommand():
	def __init__(self):
		self.command   = SMTPCommand.RSET

	def construct(self):
		pass

	def toBytes(self):
		return self.command + b'\r\n'

class SMTPDATACommand():
	def __init__(self):
		self.command   = SMTPCommand.DATA
		self.emailData = None #will be a list!

	def construct(self, emaildata):
		self.emailData = emaildata

	def toBytes(self):
		return [self.command.name.encode('ascii') + b'\r\n', self.emailData.replace('\r\n','\n').encode('ascii') + b'\r\n.\r\n']

class SMTPRCPTCommand():
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



class SMTPMAILCommand():
	def __init__(self):
		self.command = SMTPCommand.MAIL
		self.emailFrom = None

	def construct(self, emailAddress):
		if not EMAIL_REGEX.match(emailAddress):
			raise Exception('emailAddress not an email address!')
		else:
			self.emailFrom = emailAddress

	def toBytes(self):
		return self.command.name.encode('ascii') + b' <' + str(self.emailFrom).encode('ascii') + b'>\r\n'

class SMTPHELOorEHLOCommand():
	def __init__(self):
		self.command = SMTPCommand.HELO
		self.domain  = None
		self.address = None

	def contruct(self, DomainorAddress):
		try:
			self.address = ipaddress.ip_address(DomainorAddress)
		except:
			pass
		else:
			self.domain = domain

	def toBytes(self):
		if self.domain is not None:
			return self.command.name.encode('ascii') + b' ' + self.domain.encode('ascii') + b'\r\n'
		elif self.address is not None:
			return self.command.name.encode('ascii') + b' ' + str(self.address).encode('ascii') + b'\r\n'
		else:
			raise Exception('Either domain or address must be specified')