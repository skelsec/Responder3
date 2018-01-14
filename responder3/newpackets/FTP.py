#https://tools.ietf.org/html/rfc959
import enum

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
	XXXX = enum.auto()

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

class FTPCommandParser():
	def __init__(self, strict = False, encoding = 'ascii'):
		self.ftpcommand  = None
		self.strict      = strict
		self.encoding    = encoding

	def parse(self, buff):
		raw = buff.readline()
		try:
			temp = raw[:-2].decode('ascii').split(' ')
			command = FTPCommand[temp[0]]
			if command == FTPCommand.USER:
				self.ftpcommand = FTPUSERCmd(temp[1])

			elif command == FTPCommand.PASS:
				self.ftpcommand = FTPPASSCmd(temp[1])

			else:
				self.ftpcommand = SMTPXXXXCommand()
				self.ftpcommand.raw_data = raw

		except Exception as e:
			print(str(e))
			self.ftpcommand = SMTPXXXXCommand()
			self.ftpcommand.raw_data = raw

		return self.ftpcommand


class FTPCommandBASE():
	def __init__(self):
		self.cmd = None

	def toBytes(self):
		return self.cmd.name.encode('ascii') + b' ' + self.params.encode('ascii') + b'\r\n'

	def __repr__(self):
		t  = '== FTP Command == \r\n'
		t += 'Command: %s\r\n' % self.cmd.name
		t += 'Params : %s\r\n' % (''.join(self.params) if self.params is not None else 'NONE')
		return t

class FTPUSERCmd(FTPCommandBASE):
	def __init__(self, username):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.USER
		self.params = [username]

class FTPPASSCmd(FTPCommandBASE):
	def __init__(self, password):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.PASS
		self.params = [password]


class FTPACCTCmd(FTPCommandBASE):
	def __init__(self, account):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.ACCT
		self.params = [account]

class FTPCWDCmd(FTPCommandBASE):
	def __init__(self, pathname):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.CWD
		self.params = [pathname]

class FTPCDUPCmd(FTPCommandBASE):
	def __init__(self):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.CDUP

class FTPSMNTCmd(FTPCommandBASE):
	def __init__(self, pathname):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.SMNT
		self.params = [pathname]

class FTPREINCmd(FTPCommandBASE):
	def __init__(self):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.REIN

class FTPREINCmd(FTPCommandBASE):
	def __init__(self):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.QUIT

class FTPPORTCmd(FTPCommandBASE):
	#FTPPort should be a seperate object
	#
	def __init__(self, FTPPort):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.PORT
		self.params = [FTPPort]

class FTPPASVCmd(FTPCommandBASE):
	def __init__(self):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.PASV


class FTPTYPECmd(FTPCommandBASE):
	#FTPTypes should be a seperate object
	#
	def __init__(self, FTPTypes):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.TYPE
		self.params = [str(FTPTypes)]

class FTPSTRUCmd(FTPCommandBASE):
	#FTPFileStructure should be an enum
	#
	def __init__(self, fileStructure):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.STRU
		self.params = [fileStructure.name]

class FTPRETRCmd(FTPCommandBASE):
	def __init__(self, pathName):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.RETR
		self.params = [pathName]

class FTPSTORCmd(FTPCommandBASE):
	def __init__(self, pathName):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.STOR
		self.params = [pathName]

class FTPSTOUCmd(FTPCommandBASE):
	def __init__(self, pathName):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.STOU
		self.params = [pathName]

class FTPAPPECmd(FTPCommandBASE):
	def __init__(self, pathName):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.APPE
		self.params = [pathName]

class FTPALLOCmd(FTPCommandBASE):
	def __init__(self, size):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.ALLO
		self.params = [size]

class FTPRESTCmd(FTPCommandBASE):
	def __init__(self, marker):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.REST
		self.params = [marker]

class FTPRNFRCmd(FTPCommandBASE):
	def __init__(self, oldPathName):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.RNFR
		self.params = [oldPathName]

class FTPRNTOCmd(FTPCommandBASE):
	def __init__(self, newPathName):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.RNTO
		self.params = [newPathName]

class FTPABORCmd(FTPCommandBASE):
	def __init__(self):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.ABOR

class FTPDELECmd(FTPCommandBASE):
	def __init__(self, pathName):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.DELE
		self.params = [pathName]

class FTPRMDCmd(FTPCommandBASE):
	def __init__(self, pathName):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.RMD
		self.params = [pathName]

class FTPMKDCmd(FTPCommandBASE):
	def __init__(self, pathName):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.MKD
		self.params = [pathName]

class FTPPWDCmd(FTPCommandBASE):
	def __init__(self):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.PWD


class FTPLISTCmd(FTPCommandBASE):
	def __init__(self, pathName):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.LIST
		self.params = [pathName]

class FTPNLISTCmd(FTPCommandBASE):
	def __init__(self, pathName = None):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.NLIST
		self.params = [pathName]

class FTPNLISTCmd(FTPCommandBASE):
	def __init__(self, pathName = None):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.NLIST
		self.params = [pathName]

class FTPSITECmd(FTPCommandBASE):
	def __init__(self, pathName = None):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.SITE

class FTPSYSTCmd(FTPCommandBASE):
	def __init__(self):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.SYST

class FTPSTATCmd(FTPCommandBASE):
	def __init__(self):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.STAT

class FTPHELPCmd(FTPCommandBASE):
	def __init__(self):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.HELP

class FTPNOOPCmd(FTPCommandBASE):
	def __init__(self):
		FTPCommandBASE.__init__(self)
		self.cmd    = FTPCommand.NOOP

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

	def toBytes(self):
		if len(self.msg) == 1:
			return b'%s %s\r\n' % (self.code.encode(self.encoding), self.msg[0].encode(self.encoding))
		elif len(self.msg) == 2:
			temp  = b'%s-%s' % (self.code.encode(self.encoding) , self.msg[0].encode(self.encoding))
			return temp + b'%s %s' % (self.code.encode(self.encoding) , self.msg[1].encode(self.encoding))
		else:
			temp  = b'%s-%s' % (self.code.encode(self.encoding) , self.msg[0].encode(self.encoding))
			temp += b'\r\n'.join(['', (m.encode(self.encoding) for m in self.msg[1:-1] )])
			return temp + b'%s %s' % (self.code.encode(self.encoding) , self.msg[-1].encode(self.encoding))

"""
class FTPReply():
	def __init__(self, buff = None):
		self.code = None
		self.msg  = None

		if buff is not None:
			self.parse(buff)

	def parse(self, buff):
		self.replyCode   = buff.read(3).decode('ascii')
		#sanity check
		FTPReplyCode[self.replyCode]
		#
		temp = buff.read(1).decode('ascii')
		self.isMultiLine  = temp == '-'
		if self.isMultiLine:
			self.replyMessage = ''
			while True:
				line = buff.readline().decode('ascii')[:-2]
				if line == '':
					raise Exception('Parsing error!')
				
				if line[:4] == str(self.replyCode) + ' ':
					self.replyMessage += line[4:]
					break
				self.replyMessage += line + '\\r\\n'

		else:
			self.replyMessage = buff.readline().decode('ascii')

	def construct(self, ftpcommandcode, reply_message = None):
		self.replyCode = str(ftpcommandcode)
		self.replyMessage = reply_message
		if self.replyMessage is None:
			self.replyMessage = FTPReplyCode[self.replyCode]
		

	def toBytes(self):
		if not self.isMultiLine:
			return b'%s %s\r\n' % (self.replyCode.encode('ascii'), self.replyMessage.encode('ascii'))
		else:
			raise Exception('Not implemented!')
		
		return t

	def __repr__(self):
		t = '== FTP Reply ==\r\n'
		t += 'Code : %s \r\n' % self.replyCode
		t += 'Code verbose: %s \r\n' % FTPReplyCode[self.replyCode]
		t += 'Reply: %s \r\n' % self.replyMessage
		return t

"""