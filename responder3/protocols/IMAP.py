
#https://tools.ietf.org/html/rfc3501
import io
import enum

class IMAPState(enum.Enum):
        NOTAUTHENTICATED = enum.auto()
        AUTHENTICATED    = enum.auto()
        SELECTED         = enum.auto()
        LOGOUT           = enum.auto()

class IMAPResponseCode(enum.Enum):
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

"""
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
"""

class IMAPCommandParser():
        #def __init__(self, strict = False, encoding = self.encoding):
        def __init__(self, strict = False, encoding = 'utf-7'):
                self.imapcommand = None
                self.strict      = strict
                self.encoding    = encoding

        def parse(self, buff):
                raw = buff.readline()
                try:
                        tag, command, *params = raw[:-2].decode(self.encoding).split(' ')
                        command = IMAPCommand[command]
                        if command == IMAPCommand.CAPABILITY:
                                self.imapcommand = IMAPCAPABILITYCommand(tag)
                        elif command == IMAPCommand.NOOP:
                                self.imapcommand = IMAPNOOPCommand(tag)
                        elif command == IMAPCommand.LOGOUT:
                                self.imapcommand = IMAPLOGOUTCommand(tag)
                        elif command == IMAPCommand.STARTTLS:
                                self.imapcommand = IMAPSTARTTLSCommand(tag)
                        elif command == IMAPCommand.AUTHENTICATE:
                                self.imapcommand = IMAPAUTHENTICATECommand(tag)
                        elif command == IMAPCommand.LOGIN:
                                self.imapcommand = IMAPLOGINCommand(tag, username= params[0], password= params[1])
                        elif command == IMAPCommand.SELECT:
                                self.imapcommand = IMAPSELECTCommand(tag)
                        elif command == IMAPCommand.EXAMINE:
                                self.imapcommand = IMAPEXAMINECommand(tag)
                        elif command == IMAPCommand.CREATE:
                                self.imapcommand = IMAPCREATECommand(tag)
                        elif command == IMAPCommand.DELETE:
                                self.imapcommand = IMAPDELETECommand(tag)
                        elif command == IMAPCommand.RENAME:
                                self.imapcommand = IMAPRENAMECommand(tag)



                        else:
                                self.imapcommand = IMAPXXXXCommand()
                                self.imapcommand.raw_data = raw

                        return  self.imapcommand

                except Exception as e:
                        print(str(e))
                        self.imapcommand = IMAPXXXXCommand()
                        self.imapcommand.raw_data = raw


class IMAPCommandBASE():
        def __init__(self, tag):
                self.tag     = tag
                self.command = None
                self.params  = None

        def toBytes(self):
                #This function can be optionally overridden in the classes inheriting this class.
                #currently only providing functionality for strings, not taking ciommand-specific "ABNF" niotation into account
                if self.args != []:
                        return b' '.join([self.tag.encode(self.encoding),self.command.name.encode(self.encoding),b' '.join([arg.encode(self.encoding) for arg in self.args])]) + b'\r\n'
                else:
                        return b' '.join([self.tag.encode(self.encoding),self.command.name.encode(self.encoding)])+ b'\r\n'

        def __repr__(self):
                t  = '== IMAP Command ==\r\n' 
                t += 'TAG     : %s\r\n' % self.tag
                t += 'Command : %s\r\n' % self.command.name
                t += 'ARGS    : %s\r\n' % (' '.join(self.params) if self.params is not None else 'NONE')
                return t


class IMAPCAPABILITYCommand(IMAPCommandBASE):
        #no args
        def __init__(self, tag):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.CAPABILITY
                self.params  = None

class IMAPNOOPCommand(IMAPCommandBASE):
        #no args
        def __init__(self, tag = '*'):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.NOOP
                self.params  = None

class IMAPLOGOUTCommand(IMAPCommandBASE):
        #no args
        def __init__(self, tag = '*'):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.NOOP
                self.params  = None

class IMAPSTARTTLSCommand(IMAPCommandBASE):
        #tag mandatory
        def __init__(self, tag):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.STARTTLS
                self.params  = None

class IMAPAUTHENTICATECommand(IMAPCommandBASE):
        #tag mandatory
        #auth mechanism mandatory
        def __init__(self, tag, authMecha):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.AUTHENTICATE
                self.params  = [authMecha]

class IMAPLOGINCommand(IMAPCommandBASE):
        #tag mandatory
        #username mandatory
        #password mandatory
        def __init__(self, tag, username, password):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.LOGIN
                self.params  = [username, password]

class IMAPSELECTCommand(IMAPCommandBASE):
        #tag mandatory
        #mailboxName mandatory
        def __init__(self, tag, mailboxName):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.SELECT
                self.params  = [mailboxName]

class IMAPSELECTCommand(IMAPCommandBASE):
        #tag mandatory
        #mailboxName mandatory
        def __init__(self, tag, mailboxName):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.SELECT
                self.params  = [mailboxName]

class IMAPEXAMINECommand(IMAPCommandBASE):
        #tag mandatory
        #mailboxName mandatory
        def __init__(self, tag, mailboxName):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.EXAMINE
                self.params  = [mailboxName]

class IMAPCREATECommand(IMAPCommandBASE):
        #tag mandatory
        #mailboxName mandatory
        def __init__(self, tag, mailboxName):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.CREATE
                self.params  = [mailboxName]

class IMAPDELETECommand(IMAPCommandBASE):
        #tag mandatory
        #mailboxName mandatory
        def __init__(self, tag, mailboxName):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.DELETE
                self.params  = [mailboxName]

class IMAPRENAMECommand(IMAPCommandBASE):
        #tag mandatory
        #mailboxName mandatory
        #newMailboxName mandatory
        def __init__(self, tag, mailboxName, newMailboxName):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.RENAME
                self.params  = [mailboxName, newMailboxName]

class IMAPSUBSCRIBECommand(IMAPCommandBASE):
        #tag mandatory
        #mailboxName mandatory
        def __init__(self, tag, mailboxName):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.SUBSCRIBE
                self.params  = [mailboxName]

class IMAPUNSUBSCRIBECommand(IMAPCommandBASE):
        #tag mandatory
        #mailboxName mandatory
        def __init__(self, tag, mailboxName):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.USUBSCRIBE
                self.params  = [mailboxName]

class IMAPLISTCommand(IMAPCommandBASE):
        #tag mandatory
        #reference name mandatory
        #mailboxName mandatory
        def __init__(self, tag, refName, mailboxName):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.LIST
                self.params  = [refName, mailboxName]

class IMAPLSUBCommand(IMAPCommandBASE):
        #tag mandatory
        #reference name mandatory
        #mailboxName mandatory
        def __init__(self, tag, refName, mailboxName):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.LSUB
                self.params  = [refName, mailboxName]

class IMAPSTATUSCommand(IMAPCommandBASE):
        #tag mandatory
        #mailboxName mandatory
        #status data item names
        def __init__(self, tag, mailboxName, statusData):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.STATUS
                self.params  = [mailboxName, statusData]

"""TODO
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

class IMAPCHECKCommand(IMAPCommandBASE):
        #tag mandatory
        def __init__(self, tag):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.CHECK
                self.params  = None

class IMAPCLOSECommand(IMAPCommandBASE):
        #tag mandatory
        def __init__(self, tag):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.CLOSE
                self.params  = None

class IMAPEXPUNGECommand(IMAPCommandBASE):
        #tag mandatory
        def __init__(self, tag):
                IMAPCommandBASE.__init__(self, tag)
                self.command = IMAPCommand.EXPUNGE
                self.params  = None

"""TODO
class IMAPSEARCHCommand(IMAPCommandBASE):
        #tag mandatory
        def __init__(self, tag):
                self.tag     = tag
                self.command = IMAPCommand.SEARCH
                self.params  = None        

class IMAPFETCHCommand(IMAPCommandBASE):
        #tag mandatory
        def __init__(self, tag):
                self.tag     = tag
                self.command = IMAPCommand.FETCH
                self.params  = None

class IMAPSTORECommand(IMAPCommandBASE):
        #tag mandatory
        def __init__(self, tag):
                self.tag     = tag
                self.command = IMAPCommand.STORE
                self.params  = None

class IMAPCOPYCommand(IMAPCommandBASE):
        #tag mandatory
        def __init__(self, tag):
                self.tag     = tag
                self.command = IMAPCommand.COPY
                self.params  = None

class IMAPUIDCommand(IMAPCommandBASE):
        #tag mandatory
        def __init__(self, tag):
                self.tag     = tag
                self.command = IMAPCommand.COPY
                self.params  = None
"""
class IMAPResponse():
        def __init__(self, tag, encoding = 'utf-7'):
                self.encoding = encoding
                self.tag    = tag
                self.status = None
                self.params = None

        def toBytes(self):
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




class IMAPOKResp(IMAPResponse):
        #tag optional
        #args optional
        def __init__(self, tag = None, msg = None):
                IMAPResponse.__init__(self, tag)
                self.status = IMAPResponseCode.OK
                self.params = [msg] if msg is not None else msg

class IMAPNOResp(IMAPResponse):
        #tag optional
        #args optional
        def __init__(self, tag = None, msg = None):
                IMAPResponse.__init__(self, tag)
                self.tag = tag
                self.status = IMAPResponseCode.NO
                self.params = [msg] if msg is not None else msg

class IMAPBADResp(IMAPResponse):
        #tag optional
        #args optional
        def __init__(self, tag = None, msg = None):
                IMAPResponse.__init__(self, tag)
                self.tag = tag
                self.status = IMAPResponseCode.BAD
                self.params = [msg] if msg is not None else msg

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

"""
class IMAPLISTResp():
        #tag optional
        #capabilities is an IMAPCapabilities object!
        def __init__(self, tag, capabilities):
                self.tag = tag
                self.status = IMAPResponseCode.LIST
                self.params = [str(capabilities)]


"""
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
class IMAPResponse():
        def __init__(self, buff = None):
                self.tag    = None
                self.status = None
                self.args   = None

                if buff is not None:
                        self.parse(buff)

        def parse(self,buff):
                temp = buff.readline()[:-2].decode(self.encoding).split(' ')
                self.tag = temp[0]
                self.status = IMAPServerResponse[temp[1]]
                self.args   = temp[2:]
                while True:
                        temp = buff.read(1).decode(self.encoding)
                        if temp != '.':
                                buff.seek(-1, io.SEEK_CUR)
                                break
                        else:
                                self.args += buff.readline()[:-2].decode(self.encoding)

        def toBytes(self):
                if self.args != []:
                        return b' '.join([self.tag.encode(self.encoding), self.status.name.encode(self.encoding),  b' '.join([arg.encode(self.encoding) for arg in self.args])]) + b'\r\n'
                else:
                        return b' '.join([self.tag.encode(self.encoding), self.status.name.encode(self.encoding)]) + b'\r\n'

        def construct(self, tag, status, args):
                self.tag    = tag
                self.status = status
                if isinstance(args, str):
                        self.args = [args]
                else:
                        self.args = args

"""


