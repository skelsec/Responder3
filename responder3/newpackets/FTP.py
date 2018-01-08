#https://tools.ietf.org/html/rfc959
import enum

class FTPCommandCode(enum.Enum):
	USER = enum.auto()#<SP> <username> <CRLF>
	PASS = enum.auto()#<SP> <password> <CRLF>
	ACCT = enum.auto()#<SP> <account-information> <CRLF>
	CWD  = enum.auto()#<SP> <pathname> <CRLF>
	CDUP = enum.auto()#<CRLF>
	SMNT = enum.auto()#<SP> <pathname> <CRLF>
	QUIT = enum.auto()#<CRLF>
	REIN = enum.auto()#<CRLF>
	PORT = enum.auto()#<SP> <host-port> <CRLF>
	PASV = enum.auto()#<CRLF>
	TYPE = enum.auto()#<SP> <type-code> <CRLF>
	STRU = enum.auto()#<SP> <structure-code> <CRLF>
	MODE = enum.auto()#<SP> <mode-code> <CRLF>
	RETR = enum.auto()#<SP> <pathname> <CRLF>
	STOR = enum.auto()#<SP> <pathname> <CRLF>
	STOU = enum.auto()#<CRLF>
	APPE = enum.auto()#<SP> <pathname> <CRLF>
	ALLO = enum.auto()#<SP> <decimal-integer> [<SP> R <SP> <decimal-integer>] <CRLF>
	REST = enum.auto()#<SP> <marker> <CRLF>
	RNFR = enum.auto()#<SP> <pathname> <CRLF>
	RNTO = enum.auto()#<SP> <pathname> <CRLF>
	ABOR = enum.auto()#<CRLF>
	DELE = enum.auto()#<SP> <pathname> <CRLF>
	RMD  = enum.auto()#<SP> <pathname> <CRLF>
	MKD  = enum.auto()#<SP> <pathname> <CRLF>
	PWD  = enum.auto()#<CRLF>
	LIST = enum.auto()#[<SP> <pathname>] <CRLF>
	NLST = enum.auto()#[<SP> <pathname>] <CRLF>
	SITE = enum.auto()#<SP> <string> <CRLF>
	SYST = enum.auto()#<CRLF>
	STAT = enum.auto()#[<SP> <pathname>] <CRLF>
	HELP = enum.auto()#[<SP> <string>] <CRLF>
	NOOP = enum.auto()#<CRLF>
	AUTH = enum.auto()
	NLIST= enum.auto()
	FEAT = enum.auto()
	EPSV = enum.auto()
	SIZE = enum.auto()

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
	'530' : "Not logged in.",
	'532' : "Need account for storing files.",
	'550' : "Requested action not taken.",  #File unavailable (e.g., file not found, no access).
	'551' : "Requested action aborted: page type unknown.", 
	'552' : "Requested file action aborted.",  #Exceeded storage allocation (for current directory or 	    dataset).
	'553' : "Requested action not taken." #File name not allowed.
}

class FTPCommand():
	def __init__(self, buff = None):
		self.command = None
		self.params  = None

		if buff is not None:
			self.parse(buff)

	def parse(self, buff):
		temp = buff.readline().decode('ascii')[:-2]
		marker = temp.find(' ')
		if marker == -1:
			self.command = FTPCommandCode[temp]
		else:
			self.command = FTPCommandCode[temp[:marker]]
		#TODO implement all possible commands :) 
		if self.command == FTPCommandCode.USER:
			self.params = {'username': temp[marker+1:]}

		elif self.command == FTPCommandCode.PASS:
			self.params = {'password': temp[marker+1:]}

		elif self.command == FTPCommandCode.ACCT:
			self.params = {'account-information': temp[marker+1:]}

		elif self.command in [  FTPCommandCode.CWD, 
								FTPCommandCode.SMNT,
								FTPCommandCode.RETR,
								FTPCommandCode.STOR,
								FTPCommandCode.APPE,
								FTPCommandCode.RNFR,
								FTPCommandCode.RNTO,
								FTPCommandCode.DELE,
								FTPCommandCode.RMD,
								FTPCommandCode.MKD,
								FTPCommandCode.SIZE
			                 ]:
			self.params = {'pathname': temp[marker+1:]}

		elif self.command == FTPCommandCode.TYPE:
			self.params = {'type-code': temp[marker+1:]}

		elif self.command == FTPCommandCode.STRU:
			self.params = {'structure-code': temp[marker+1:]}

		elif self.command == FTPCommandCode.MODE:
			self.params = {'mode-code': temp[marker+1:]}

		elif self.command == FTPCommandCode.ALLO:
			self.params = {'decimal-integer': temp[marker+1:]}

		elif self.command == FTPCommandCode.REST:
			self.params = {'marker': temp[marker+1:]}
			
		elif self.command in [ FTPCommandCode.LIST, 
							   FTPCommandCode.NLIST, 
							   FTPCommandCode.STAT, 
							   FTPCommandCode.HELP
							 ]:
			self.params = {'pathname': temp[marker+1:]}

		elif self.command == FTPCommandCode.PORT:
			self.params = {'hst-port': int(temp[marker+1:])}

		elif self.command in [ FTPCommandCode.CDUP, 
							   FTPCommandCode.QUIT,
							   FTPCommandCode.REIN,
							   FTPCommandCode.PASV,
							   FTPCommandCode.STOU,
							   FTPCommandCode.ABOR,
							   FTPCommandCode.PWD,
							   FTPCommandCode.SYST,
							   FTPCommandCode.NOOP
							 ]:
			self.params = None
		
		elif self.command in [FTPCommandCode.HELP, FTPCommandCode.SITE]:
			self.params = {'string': temp[marker+1:]}

		elif self.command == FTPCommandCode.AUTH:
			self.params = {'auth-mode': temp[marker+1:]}


	def contruct(self, ftpcommand, params = None):
		"""
		ftpcommand is FTPCommandCode
		params depends on the command, bu be aware it's not completely implemented now!
		"""
		self.command = ftpcommand

		if self.command == FTPCommandCode.USER:
			self.params = {'username': params}

		elif self.command == FTPCommandCode.PASS:
			self.params = {'password': params}

		elif self.command == FTPCommandCode.ACCT:
			self.params = {'account-information': params}

		elif self.command in [  FTPCommandCode.CWD, 
								FTPCommandCode.SMNT,
								FTPCommandCode.RETR,
								FTPCommandCode.STOR,
								FTPCommandCode.APPE,
								FTPCommandCode.RNFR,
								FTPCommandCode.RNTO,
								FTPCommandCode.DELE,
								FTPCommandCode.RMD,
								FTPCommandCode.MKD,
			                 ]:
			self.params = {'pathname': params}

		else:
			#TODO make the temple for the rest of the commands
			self.params = params


	def toBytes(self):
		return self.command.name.encode('ascii') + b' ' + self.params.encode('ascii') + b'\r\n'

	def __repr__(self):
		t  = '== FTP Command == \r\n'
		t += 'Command: %s\r\n' % self.command.name
		t += 'Params : %s\r\n' % repr(self.params)

		return t



class FTPReply():
	def __init__(self, buff = None):
		self.isMultiLine  = False
		self.replyCode    = None
		self.replyMessage = None

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
				line = buff.readline().decode('ascii')
				
				if line[4:] == str(self.replyCode) + ' ':
					self.replyMessage += line[4:]
					break
				self.replyMessage += line

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