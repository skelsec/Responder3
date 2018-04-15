
#https://tools.ietf.org/html/rfc3501
import io
import enum
import asyncio

from responder3.core.commons import read_element, Credential
from responder3.core.asyncio_helpers import *

class IMAPVersion(enum.Enum):
	IMAP    = 'IMAP'
	IMAPv4    = 'IMAPv4'
	IMAP4rev1 = 'IMAP4rev1'

class IMAPAuthMethod(enum.Enum):
	PLAIN = enum.auto()

class IMAPState(enum.Enum):
	NOTAUTHENTICATED = enum.auto()
	AUTHENTICATED    = enum.auto()
	SELECTED         = enum.auto()
	LOGOUT           = enum.auto()

class IMAPResponse(enum.Enum):
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

class IMAPCommand(enum.Enum):
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
	XXXX         = enum.auto()



class IMAPCommandParser():
	#def __init__(self, strict = False, encoding = self.encoding):
	def __init__(self, strict = False, encoding = 'utf-7'):
		self.imapcommand = None
		self.strict      = strict
		self.encoding    = encoding
		self.timeout     = 10

	@asyncio.coroutine
	def from_streamreader(self, reader):
		cmd = yield from readline_or_exc(reader, timeout = self.timeout)
		return self.from_bytes(cmd)

	def from_bytes(self, bbuff):
		return self.from_buffer(io.BytesIO(bbuff))

	def from_buffer(self, buff):
		line = buff.readline()
		try:
			tag, command, *params = line.strip().decode(self.encoding).split(' ')
			if command in IMAPCommand.__members__:
				cmd = IMAPCMD[IMAPCommand[command]].from_bytes(line)
			else:
				cmd = IMAPXXX.from_bytes(line)
			return cmd

		except Exception as e:
			print(str(e))
			return IMAPXXX.from_bytes(line)


class IMAPResponseParser():
	def __init__(self, strict = False, encoding = 'utf-7'):
		self.imapcommand = None
		self.strict      = strict
		self.encoding    = encoding
		self.timeout     = 10

	@asyncio.coroutine
	def from_streamreader(self, reader):
		resp = yield from readline_or_exc(reader, timeout = self.timeout)
		return self.from_bytes(resp)

	def from_bytes(self, bbuff):
		return self.from_buffer(io.BytesIO(bbuff))

	def from_buffer(self, buff):
		line = buff.readline()
		try:
			tag, *params = line.strip().decode(self.encoding).split(' ')
			if tag == '*':
				command = params[0]
				if command in IMAPResponse.__members__:
					resp = IMAPRESP[IMAPResponse[command]].from_bytes(line)
				else:
					resp = IMAPXXX.from_bytes(line)
			else:
				if params[0] == 'OK':
					resp = IMAPOKResp.from_bytes(line)
				elif params[0] == 'BAD':
					resp = IMAPBADResp.from_bytes(line)
				elif params[0] == 'NO':
					resp = IMAPNOResp.from_bytes(line)
				else:
					resp = IMAPXXX.from_bytes(line)

			return resp

		except Exception as e:
			print(str(e))
			return IMAPXXX.from_bytes(line)


def read_list(line):
	temp = read_element(line, marker = '(', marker_end = ')')
	return temp[1:-1].split(' ')


class IMAPXXX():
	def __init__(self):
		self.data = None

	def from_bytes(bbuff):
		cmd = IMAPXXX()
		cmd.data = bbuff
		return cmd

	def __str__(self):
		return '%s' % self.data

class IMAPCAPABILITYCmd():
	# Arguments:  none
	# Responses:  REQUIRED untagged response: CAPABILITY
	# Result: [OK, BAD]
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.CAPABILITY

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPCAPABILITYCmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPCAPABILITYCmd()
		cmd.tag, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[bbuff]
		return cmd

	def construct(tag):
		cmd = IMAPCAPABILITYCmd()
		cmd.tag = tag
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s\r\n' % self.tag, self.command.value).encode(encoding)

	def __str__(self):
		return '%s %s\r\n' % (self.tag, self.command.name)

class IMAPCAPABILITYResp():
	#must be untagged!
	def __init__(self):
		self.tag     = '*'
		self.command = IMAPCommand.CAPABILITY
		self.capabilities = []

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPCAPABILITYResp.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		resp = IMAPCAPABILITYResp()
		resp.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff)
		resp.command = IMAPCommand[t]
		resp.capabilities = bbuff.split(' ')

		return resp

	def construct(supported_versions, supported_auth_types, additional_capabilities, tag = '*'):
		resp = IMAPCAPABILITYResp()
		resp.tag = tag
		for cap in supported_versions:
			resp.capabilities.append(cap.name)
		for cap in additional_capabilities:
			resp.capabilities.append(cap.name)
		for auth in supported_auth_types:
			resp.capabilities.append('AUTH=%s' % auth)

		return resp

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s\r\n' % (self.tag, self.command.name, ' '.join(self.capabilities))).encode(encoding)

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.command.name, ' '.join(self.capabilities))


class IMAPNOOPCmd():
	#Arguments:  none
	#Responses:  no specific responses for this command (but see below)
	#Result:     OK,BAD 
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.NOOP

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPNOOPCmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPNOOPCmd()
		cmd.tag, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[bbuff]
		return cmd

	def construct(tag):
		cmd = IMAPNOOPCmd()
		cmd.tag = tag
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s\r\n' % self.tag, self.command.value).encode(encoding)

	def __str__(self):
		return '%s %s\r\n' % (self.tag, self.command.name)

class IMAPLOGOUTCmd():
	#Arguments:  none
	#Responses:  REQUIRED untagged response: BYE
	#Result:     OK,BAD - command unknown or arguments invalid
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.NOOP

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPLOGOUTCmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPLOGOUTCmd()
		cmd.tag, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[bbuff]
		return cmd

	def construct(tag):
		cmd = IMAPLOGOUTCmd()
		cmd.tag = tag
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s\r\n' % self.tag, self.command.value).encode(encoding)

	def __str__(self):
		return '%s %s\r\n' % (self.tag, self.command.name)

class IMAPSTARTTLSCmd():
	#Arguments:  none
	#Responses:  no specific response for this command
	# Result:     OK, BAD
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.STARTTLS

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPSTARTTLSCmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPSTARTTLSCmd()
		cmd.tag, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[bbuff]
		return cmd

	def construct(tag):
		cmd = IMAPSTARTTLSCmd()
		cmd.tag = tag
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s\r\n' % self.tag, self.command.value).encode(encoding)

	def __str__(self):
		return '%s %s\r\n' % (self.tag, self.command.name)

class IMAPAUTHENTICATECmd():
	#Arguments:  authentication mechanism name
	#Responses:  continuation data can be requested
	#Result:     OK,NO,BAD 
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.AUTHENTICATE
		self.authmecha = None

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPAUTHENTICATECmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		print('Here!')
		try:
			bbuff = bbuff.decode(encoding).strip()
			cmd = IMAPAUTHENTICATECmd()
			cmd.tag, bbuff = read_element(bbuff)
			t, bbuff = read_element(bbuff)
			cmd.command = IMAPCommand[t]
			cmd.authmecha = bbuff
			return cmd
		except Exception as e:
			print(str(e))
			raise e

	def construct(tag, authmecha):
		cmd = IMAPAUTHENTICATECmd()
		cmd.tag = tag
		cmd.authmecha = authmecha
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s \r\n' % self.tag, self.command.value, self.authmecha).encode(encoding)

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.command.name, self.authmecha)

class IMAPLOGINCmd():
	#Arguments:  user name,password
	#Responses:  no specific responses for this command
	#Result:     OK,NO,BAD
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.LOGIN
		self.username = None
		self.password = None

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPLOGINCmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPLOGINCmd()
		cmd.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[t]
		cmd.username, bbuff = read_element(bbuff)
		cmd.password = bbuff
		return cmd
		

	def construct(tag, username, password):
		cmd = IMAPLOGINCmd()
		cmd.tag = tag
		cmd.username = username
		cmd.password = password
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s %s\r\n' % self.tag, self.command.value, self.username, self.password).encode(encoding)

	def __str__(self):
		return '%s %s %s %s\r\n' % (self.tag, self.command.name, self.username, self.password)

class IMAPSELECTCmd():
	#Arguments:  mailbox name
	#Responses:  REQUIRED untagged responses: FLAGS, EXISTS, RECENT
    #            REQUIRED OK untagged responses:  UNSEEN,  PERMANENTFLAGS,
    #            UIDNEXT, UIDVALIDITY
	#Result:     OK,NO,BAD - command unknown or arguments invalid
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.SELECT
		self.mailboxname = None

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPSELECTCmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		print('Here!')
		try:
			bbuff = bbuff.decode(encoding).strip()
			cmd = IMAPSELECTCmd()
			cmd.tag, bbuff = read_element(bbuff)
			t, bbuff = read_element(bbuff)
			cmd.command = IMAPCommand[t]
			cmd.mailboxname = bbuff
			return cmd
		except Exception as e:
			print(str(e))
			raise e

	def construct(tag, mailboxname):
		cmd = IMAPSELECTCmd()
		cmd.tag = tag
		cmd.mailboxname = mailboxname
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s\r\n' % self.tag, self.command.value, self.mailboxname).encode(encoding)

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.command.name, self.mailboxname)


class IMAPEXAMINECmd():
	#Arguments:  mailbox name
	#Responses:  REQUIRED untagged responses: FLAGS, EXISTS, RECENT
	#            REQUIRED OK untagged responses:  UNSEEN,  PERMANENTFLAGS,
	#            UIDNEXT, UIDVALIDITY
	#Result:     OK,NO,BAD - command unknown or arguments invalid
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.EXAMINE
		self.mailboxname = None

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPEXAMINECmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPEXAMINECmd()
		cmd.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[t]
		cmd.mailboxname = bbuff
		return cmd

	def construct(tag, mailboxname):
		cmd = IMAPEXAMINECmd()
		cmd.tag = tag
		cmd.mailboxname = mailboxname
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s\r\n' % self.tag, self.command.value, self.mailboxname).encode(encoding)

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.command.name, self.mailboxname)

class IMAPCREATECmd():
	#Arguments:  mailbox name
	#Responses:  no specific responses for this command
	#Result:     OK,NO,BAD - command unknown or arguments invalid
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.CREATE
		self.mailboxname = None

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPCREATECmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPCREATECmd()
		cmd.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[t]
		cmd.mailboxname = bbuff
		return cmd

	def construct(tag, mailboxname):
		cmd = IMAPCREATECmd()
		cmd.tag = tag
		cmd.mailboxname = mailboxname
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s\r\n' % self.tag, self.command.value, self.mailboxname).encode(encoding)

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.command.name, self.mailboxname)

class IMAPDELETECmd():
	#Arguments:  mailbox name
	#Responses:  no specific responses for this command
	#Result:     OK,NO,BAD
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.DELETE
		self.mailboxname = None

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPDELETECmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPDELETECmd()
		cmd.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[t]
		cmd.mailboxname = bbuff
		return cmd


	def construct(tag, mailboxname):
		cmd = IMAPDELETECmd()
		cmd.tag = tag
		cmd.mailboxname = mailboxname
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s\r\n' % self.tag, self.command.value, self.mailboxname).encode(encoding)

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.command.name, self.mailboxname)

class IMAPRENAMECmd():
	#Arguments:  existing mailbox name
	#           new mailbox name
	#Responses:  no specific responses for this command
	#Result:     OK,NO,BAD
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.RENAME
		self.mailboxname = None
		self.newmailboxname = None

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPRENAMECmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPRENAMECmd()
		cmd.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[t]
		cmd.mailboxname = bbuff
		return cmd
	def construct(tag, mailboxname,newmailboxname):
		cmd = IMAPRENAMECmd()
		cmd.tag = tag
		cmd.mailboxname = mailboxname
		cmd.newmailboxname = newmailboxname
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s %s\r\n' % self.tag, self.command.value, self.mailboxname, self.newmailboxname).encode(encoding)

	def __str__(self):
		return '%s %s %s %s\r\n' % (self.tag, self.command.name, self.mailboxname, self.newmailboxname)

class IMAPSUBSCRIBECmd():
	#Arguments:  mailbox	
	#Responses:  no specific responses for this command
	#Result:     OK,NO,BAD
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.SUBSCRIBE
		self.mailboxname = None

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPSUBSCRIBECmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPSUBSCRIBECmd()
		cmd.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[t]
		cmd.mailboxname = bbuff
		return cmd

	def construct(tag, mailboxname):
		cmd = IMAPSUBSCRIBECmd()
		cmd.tag = tag
		cmd.mailboxname = mailboxname
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s\r\n' % self.tag, self.command.value, self.mailboxname).encode(encoding)

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.command.name, self.mailboxname)

class IMAPUNSUBSCRIBECmd():
	#Arguments:  mailbox	
	#Responses:  no specific responses for this command
	#Result:     OK,NO,BAD
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.UNSUBSCRIBE
		self.mailboxname = None

	def from_buffer(buff, encoding = 'utf-7'):
		return IMAPUNSUBSCRIBECmd.from_bytes(buff.readline(),encoding)

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		cmd = IMAPUNSUBSCRIBECmd()
		cmd.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff)
		cmd.command = IMAPCommand[t]
		cmd.mailboxname = bbuff
		return cmd

	def construct(tag, mailboxname):
		cmd = IMAPUNSUBSCRIBECmd()
		cmd.tag = tag
		cmd.mailboxname = mailboxname
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s\r\n' % self.tag, self.command.value, self.mailboxname).encode(encoding)

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.command.name, self.mailboxname)

class IMAPLISTCmd():
	#tag mandatory
	#reference name mandatory
	#mailboxName mandatory
	def __init__(self):
		self.tag     = None
		self.command      = IMAPCommand.LIST
		self.refname      = None
		self.mailboxname  = None

	def construct(refname,mailboxname, tag = '*'):
		cmd = IMAPLISTCmd()
		cmd.refname = refname
		cmd.mailboxname = mailboxname
		cmd.tag = tag
		return cmd

	def from_params(tag = '*', params = None):
		cmd = IMAPLISTCmd()
		cmd.tag = tag
		cmd.refname = params[0]
		cmd.mailboxname = params[1]
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s %s\r\n' % self.tag, self.command.value, self.refname, self.mailboxname).encode(encoding)

class IMAPLSUBCmd():
	#tag mandatory
	#reference name mandatory
	#mailboxName mandatory
	def __init__(self):
		self.tag     = None
		self.command      = IMAPCommand.LSUB
		self.refname      = None
		self.mailboxname  = None

	def construct(refname,mailboxname, tag = '*'):
		cmd = IMAPLSUBCmd()
		cmd.refname = refname
		cmd.mailboxname = mailboxname
		cmd.tag = tag
		return cmd

	def from_params(tag = '*', params = None):
		cmd = IMAPLSUBCmd()
		cmd.tag = tag
		cmd.refname = params[0]
		cmd.mailboxname = params[1]
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s %s\r\n' % self.tag, self.command.value, self.refname, self.mailboxname).encode(encoding)

"""TODO
class IMAPSTATUSCmd():
	#tag mandatory
	#mailboxName mandatory
	#status data item names
	def __init__(self):
		self.tag     = None
		self.command      = IMAPCommand.LSUB
		self.refname      = None
		self.mailboxname  = None

	def construct(refname,mailboxname, tag = '*'):
		cmd = IMAPLSUBCmd()
		cmd.refname = refname
		cmd.mailboxname = mailboxname
		cmd.tag = tag
		return cmd

	def from_params(tag = '*', params = None):
		cmd = IMAPLSUBCmd()
		cmd.tag = tag
		cmd.refname = params[0]
		cmd.mailboxname = params[1]
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s %s\r\n' % self.tag, self.command.value, self.refname, self.mailboxname).encode(encoding)


class IMAPAPPENDCommand(IMAPCommandBASE):
	#tag mandatory
	#mailboxName mandatory
	#OPTIONAL flag parenthesized list
	#OPTIONAL date/time string
	#message literal
	def __init__(self, tag, mailboxName, statusData):
		self.tag     = tag
		self.command = IMAPCommand.APPEND
		self.params  = [mailboxName, statusData]
"""

class IMAPCHECKCmd():
	#no args
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.CHECK

	def construct(tag = '*'):
		cmd = IMAPCHECKCmd()
		cmd.tag = tag
		return cmd

	def from_params(tag = '*', params = None):
		cmd = IMAPCHECKCmd()
		cmd.tag = tag
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s\r\n' % self.tag, self.command.value).encode(encoding)

class IMAPCLOSECmd():
	#no args
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.CLOSE

	def construct(tag = '*'):
		cmd = IMAPCLOSECmd()
		cmd.tag = tag
		return cmd

	def from_params(tag = '*', params = None):
		cmd = IMAPCLOSECmd()
		cmd.tag = tag
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s\r\n' % self.tag, self.command.value).encode(encoding)

class IMAPEXPUNGECmd():
	#no args
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.EXPUNGE

	def construct(tag = '*'):
		cmd = IMAPEXPUNGECmd()
		cmd.tag = tag
		return cmd

	def from_params(tag = '*', params = None):
		cmd = IMAPEXPUNGECmd()
		cmd.tag = tag
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s\r\n' % self.tag, self.command.value).encode(encoding)

"""TODO
class IMAPSEARCHCommand():
	#tag mandatory
	def __init__(self, tag):
		self.tag     = tag
		self.command = IMAPCommand.SEARCH
		self.params  = None	

class IMAPFETCHCommand():
	#tag mandatory
	def __init__(self, tag):
		self.tag     = tag
		self.command = IMAPCommand.FETCH
		self.params  = None

class IMAPSTORECommand():
	#tag mandatory
	def __init__(self, tag):
		self.tag     = tag
		self.command = IMAPCommand.STORE
		self.params  = None
"""

class IMAPCOPYCmd():
	#tag mandatory
	def __init__(self):
		self.tag     = None
		self.command = IMAPCommand.COPY
		self.sequence    = None
		self.mailboxname = None

	def construct(sequence, mailboxname,tag = '*'):
		cmd = IMAPCOPYCmd()
		cmd.tag = tag
		cmd.sequence = sequence
		cmd.mailboxname = mailboxname
		return cmd

	def from_params(tag = '*', params = None):
		cmd = IMAPCOPYCmd()
		cmd.tag = tag
		cmd.sequence = params[0]
		cmd.mailboxname = params[1]
		return cmd

	def to_bytes(self, encoding = 'utf-7'):
		return ('%s %s %s %s\r\n' % self.tag, self.command.value, self.sequence, self.mailboxname).encode(encoding)

"""TODO
class IMAPUIDCommand():
	#tag mandatory
	def __init__(self, tag):
		self.tag     = tag
		self.command = IMAPCommand.COPY
		self.params  = None
"""

class IMAPOKResp():
	#tag optional
	#args optional
	def __init__(self):
		self.tag = '*'
		self.status = IMAPResponse.OK
		self.args = []

	def construct(args, tag = '*'):
		resp = IMAPOKResp()
		resp.tag = tag
		if isinstance(args, list):
			resp.args = args
		else:
			resp.args = [args]
		return resp

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		resp = IMAPOKResp()
		resp.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff, toend = True)
		resp.status = IMAPResponse[t]
		if bbuff != '':
			resp.args = bbuff.split(' ')

		return resp

	def to_bytes(self):
		return ('%s %s %s\r\n' % (self.tag, self.status.name, ' '.join(self.args) if len(self.args) > 0 else '')).encode('utf-7')

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.status.name, ' '.join(self.args) if len(self.args) > 0 else '')

class IMAPBYEResp():
	#tag optional
	#args optional
	def __init__(self):
		self.tag = '*'
		self.status = IMAPResponse.BYE
		self.args = []

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		resp = IMAPBYEResp()
		resp.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff, toend = True)
		resp.status = IMAPResponse[t]
		if bbuff != '':
			resp.args = bbuff.split(' ')

		return resp

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.status.name, ' '.join(self.args) if len(self.args) > 0 else '')

class IMAPBADResp():
	#tag optional
	#args optional
	def __init__(self):
		self.tag = '*'
		self.status = IMAPResponse.BAD
		self.args = []

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		resp = IMAPBADResp()
		resp.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff, toend = True)
		resp.status = IMAPResponse[t]
		if bbuff != '':
			resp.args = bbuff.split(' ')

		return resp

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.status.name, ' '.join(self.args) if len(self.args) > 0 else '')

class IMAPNOResp():
	#tag optional
	#args optional
	def __init__(self):
		self.tag = '*'
		self.status = IMAPResponse.NO
		self.args = []

	def from_bytes(bbuff, encoding = 'utf-7'):
		bbuff = bbuff.decode(encoding).strip()
		resp = IMAPNOResp()
		resp.tag, bbuff = read_element(bbuff)
		t, bbuff = read_element(bbuff, toend = True)
		resp.status = IMAPResponse[t]
		if bbuff != '':
			resp.args = bbuff.split(' ')

		return resp

	def __str__(self):
		return '%s %s %s\r\n' % (self.tag, self.status.name, ' '.join(self.args) if len(self.args) > 0 else '')


class IMAPAuthHandler:
	def __init__(self, authtype = IMAPAuthMethod.PLAIN, creds = None):
		if authtype == IMAPAuthMethod.PLAIN:
			self.authenticator = IMAPPlainAuth(creds)
		else:
			raise NotImplementedError

	def do_AUTH(self, cmd):
		return self.authenticator.verify_creds(cmd)


class IMAPPlainAuth:
	def __init__(self, creds):
		self.creds = creds

	def verify_creds(self, cmd):
		c = IMAPPlainCred(cmd.username, cmd.password)
		if self.creds is None:
			return True, c.toCredential()
		else:
			if c.username in self.creds:
				if self.creds[c.username] == c.passwrod:
					return True, c.toCredential()

			else:
				return False, c.toCredential()

		return False, c.toCredential()


class IMAPPlainCred:
	def __init__(self, username, password):
		self.username = username
		self.password = password

	def toCredential(self):
		return Credential('PLAIN', 
			username = self.username,
			password = self.password,
			fullhash = '%s:%s' % (self.username, self.password)
		)

"""
class IMAPResponse():
	def __init__(self, tag, encoding = 'utf-7'):
		self.encoding = encoding
		self.tag    = tag
		self.status = None
		self.params = None

	def to_bytes(self):
		if self.tag is None: 
			self.tag = '*'

		if self.params is None:
			return b' '.join([self.tag.encode(self.encoding), self.status.name.encode(self.encoding)]) + b'\r\n'
		else:
			return b' '.join([self.tag.encode(self.encoding), self.status.name.encode(self.encoding),  b' '.join([param.encode(self.encoding) for param in self.params])]) + b'\r\n'

	def __repr__(self):
		t  = '== IMAP Response ==\r\n' 
		t += 'STATUS: %s\r\n' % self.status.name
		t += 'ARGS  : %s\r\n' % self.args
		return t




class IMAPPREAUTHResp(IMAPResponse):
	#always untagged
	#args optional
	def __init__(self, msg = None):
		IMAPResponse.__init__(self, tag)
		self.status = IMAPResponseCode.PREAUTH
		self.params = [msg] if msg is not None else msg

class IMAPBYEResp(IMAPResponse):
	#always untagged
	#args optional
	def __init__(self, msg = None):
		IMAPResponse.__init__(self, tag)
		self.status = IMAPResponseCode.BYE
		self.params = [msg] if msg is not None else msg


class IMAPCAPABILITYResp(IMAPResponse):
	#tag optional
	#capabilities is an IMAPCapabilities object!
	def __init__(self, capabilities, tag=None):
		IMAPResponse.__init__(self, tag)
		self.status = IMAPResponseCode.CAPABILITY
		self.params = [str(capabilities)]


class IMAPCapabilities():
	def __init__(self, authMethods):
		self.authMethods  = authMethods
		self.capabilities = []

	def __str__(self):
		return ' '.join(self.capabilities) + ' ' + str(self.authMethods)

class IMAPAuthMethods():
	def __init__(self, methods = ['PLAIN']):
		self.methods = methods

	def __str__(self):
		return ' AUTH='.join(['']+self.methods).strip()
"""

IMAPRESP = {
	IMAPResponse.CAPABILITY   : IMAPCAPABILITYResp,
	IMAPResponse.BYE   : IMAPBYEResp,
	IMAPResponse.OK   : IMAPOKResp,
	IMAPResponse.BAD   : IMAPBADResp,
}


IMAPCMD = {
	IMAPCommand.CAPABILITY   : IMAPCAPABILITYCmd,
	IMAPCommand.NOOP         : IMAPNOOPCmd,
	IMAPCommand.LOGOUT       : IMAPLOGOUTCmd,
	IMAPCommand.STARTTLS     : IMAPSTARTTLSCmd,
	IMAPCommand.AUTHENTICATE : IMAPAUTHENTICATECmd,
	IMAPCommand.LOGIN        : IMAPLOGINCmd,
	IMAPCommand.SELECT       : IMAPSELECTCmd,
	IMAPCommand.EXAMINE      : IMAPEXAMINECmd,
	IMAPCommand.CREATE       : IMAPCREATECmd,
	IMAPCommand.DELETE       : IMAPDELETECmd,
	IMAPCommand.RENAME       : IMAPRENAMECmd,
	IMAPCommand.SUBSCRIBE    : IMAPSUBSCRIBECmd,
	IMAPCommand.UNSUBSCRIBE  : IMAPUNSUBSCRIBECmd,
	IMAPCommand.LIST         : IMAPLISTCmd,
	IMAPCommand.LSUB         : IMAPLSUBCmd,
	#IMAPCommand.STATUS       : IMAPSTATUSCmd,
	#IMAPCommand.APPEND       : IMAPAPPENDCmd,
	#IMAPCommand.CLIENT       : IMAPCLIENTCmd,
	#IMAPCommand.CHECK        : IMAPCHECKCmd,
	#IMAPCommand.CLOSE        : IMAPCLOSECmd,
	#IMAPCommand.EXPUNGE      : IMAPEXPUNGECmd,
	#IMAPCommand.SEARCH       : IMAPSEARCHCmd,
	#IMAPCommand.FETCH        : IMAPFETCHCmd,
	#IMAPCommand.STORE        : IMAPSTORECmd,
	#IMAPCommand.COPY         : IMAPCOPYCmd,
	#IMAPCommand.UID          : IMAPUIDCmd,
}