import io
import os
import enum
import zlib
import base64
import collections
from responder3.utils import timestamp2datetime

class HTTPVersion(enum.Enum):
	HTTP10 = 'HTTP/1.0'
	HTTP11 = 'HTTP/1.1'

class HTTPState(enum.Enum):
	UNAUTHENTICATED = enum.auto()
	AUTHENTICATED   = enum.auto()

class HTTPAuthType(enum.Enum):
	BASIC = enum.auto()
	NTLM  = enum.auto()

class HTTPContentEncoding(enum.Enum):
	IDENTITY = enum.auto()
	GZIP     = enum.auto()
	COMPRESS = enum.auto()
	DEFLATE  = enum.auto()
	BR       = enum.auto()

HTTPResponseReasons = {

	100 : 'Continue',
	101 : 'Switching Protocols',
	200 : 'OK',
	201 : 'Created',
	202 : 'Accepted',
	203 : 'Non-Authoritative Information',
	204 : 'No Content',
	205 : 'Reset Content',
	206 : 'Partial Content',
	300 : 'Multiple Choices',
	301 : 'Moved Permanently',
	302 : 'Found',
	303 : 'See Other',
	304 : 'Not Modified',
	305 : 'Use Proxy',
	307 : 'Temporary Redirect',
	400 : 'Bad Request',
	401 : 'Unauthorized',
	402 : 'Payment Required',
	403 : 'Forbidden',
	404 : 'Not Found',
	405 : 'Method Not Allowed',
	406 : 'Not Acceptable',
	407 : 'Proxy Authentication Required',
	408 : 'Request Time-out',
	409 : ' Conflict',
	410 : ' Gone',
	411 : ' Length Required',
	412 : ' Precondition Failed',
	413 : ' Request Entity Too Large',
	414 : ' Request-URI Too Large',
	415 : ' Unsupported Media Type',
	416 : ' Requested range not satisfiable',
	417 : ' Expectation Failed',
	500 : 'Internal Server Error',
	501 : 'Not Implemented',
	502 : 'Bad Gateway',
	503 : 'Service Unavailable',
	504 : 'Gateway Time-out',
	505 : 'HTTP Version not supported',

}

class HTTPRequestParser():
	def __init__(self, strict = False, encoding = 'ascii'):
		self.httprequest = None
		self.strict      = strict
		self.encoding    = encoding

	def parseHeader(self, buff):
		self.httprequest = HTTPRequest()
		buff = buff.decode(self.encoding)
		hdrs = buff.split('\r\n')
		self.httprequest.method, self.httprequest.uri, self.httprequest.version = hdrs[0].split(' ')
		for hdr in hdrs[1:]:
			marker = hdr.find(': ')
			key   = hdr[:marker]
			value = hdr[marker+2:]
			key = key.lower()
			if key == 'content-encoding':
				#TODO
				#THIS DOESNT TAKE MULTIPLE-TYPE COMPRESSION INTO ACCOUNT AND WILL FAIL!
				self.httprequest.headers[key] = ContentEncoding[value]
			else:
				self.httprequest.headers[key] = value

		if 'content-length' in self.httprequest.headers:
			return int(self.httprequest.headers['content-length'])
		else:
			return 0

	def parseBody(self, buff):
		try:
			#TODO!!
			#1. decompression
			#2. check charset, and apply that specific decoding (https://www.w3.org/International/articles/http-charset/index)
			
			decompressed_buff = b''
			decompressed_buff = buff
			self.httprequest.body = decompressed_buff.decode('utf-8')

			t = self.httprequest
			self.httprequest = None
			return t

			"""
			if 'content-encoding' in self.httprequest.headers:
				if self.httprequest.headers['content-encoding'] == ContentEncoding.IDENTITY:
					decompressed_buff = buff
				
				elif self.httprequest.headers['content-encoding'] == ContentEncoding.GZIP:
					raise Exception('Not Implemented!')
					#self.httprequest.body = zlib.decompress(body, 16+zlib.MAX_WBITS)

				elif self.httprequest.headers['content-encoding'] == ContentEncoding.COMPRESS:
					raise Exception('Not Implemented!')

				elif self.httprequest.headers['content-encoding'] == ContentEncoding.DEFLATE:
					raise Exception('Not Implemented!')

				elif self.httprequest.headers['content-encoding'] == ContentEncoding.BR:
					raise Exception('Not Implemented!')
				else:
					raise Exception('Encofding format not recognized!')

			else:
				self.httprequest.body = body

			"""

		except Exception as e:
			raise

class HTTPRequest():
	def __init__(self):
		self.method  = None
		self.uri     = None
		self.version = None
		self.headers = {}
		self.body    = None


	def __repr__(self):
		t  = '== HTTP Request ==\r\n'
		t += 'FIRST  : %s\r\n' %' '.join([self.method, self.uri, self.version])
		t += 'HEADERS: %s\r\n' % repr(self.headers)
		t += 'BODY   : \r\n %s\r\n' % repr(self.body)
		return t


class HTTPResponseBase():
	def __init__(self, session, code, body = None):
		self.version = session.HTTPVersion.value
		self.code    = str(code)
		self.reason  = HTTPResponseReasons[code] if code in HTTPResponseReasons else 'Pink kittens'
		self.body    = body
		self.headers = {}

	def toBytes(self):
		t  = '%s %s %s\r\n' % (self.version, self.code, self.reason)
		t  += "Content-Type: text/html\r\n"
		t  += "Content-Length: 0\r\n"
		for key, value in self.headers.items():
			t += key + ': ' + self.headers[key] + '\r\n'


		t += '\r\n'
		t = t.encode('ascii')
		####################################
		####################################
		## TODO!!! use specific encoding + compression when needed!!!
		if self.body is not None:
			t += self.body.encode('utf-8')

		return t



class HTTP200Resp(HTTPResponseBase):
	def __init__(self, session):
		HTTPResponseBase.__init__(self, session, 200)


class HTTP301Resp(HTTPResponseBase):
	def __init__(self, redirectURL):
		HTTPResponseBase.__init__(self, session, 200)
		self.headers['Location'] = redirectURL

class HTTP401Resp(HTTPResponseBase):
	def __init__(self, session, authType, authChallenge = None, body = None):
		HTTPResponseBase.__init__(self, session, 401, body = body)
		if authChallenge is not None:
			self.headers['WWW-Authenticate'] = '%s %s' % (authType, authChallenge)
		else:
			self.headers['WWW-Authenticate'] = '%s' % authType

class HTTPBasicAuth():
	def __init__(self, creds = None):
		self._iterations = 0
		self.creds = creds


	def handleRequest(self, req, transport, session):
		print('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
		if 'authorization' in req.headers and req.headers['authorization'][:5] == 'Basic':
			print('Authdata in! %s' % (base64.b64decode(req.headers['authorization'][5:]).decode('ascii')))

		else:
			transport.write(HTTP401Resp(session, 'Basic').toBytes())
			transport.close()

def HTTPNTLMAuthHandler(req, transport, session):
		print('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
		if 'authorization' in req.headers and req.headers['authorization'][:4] == 'NTLM':
			#print('Authdata in! %s' % (base64.b64decode(req.headers['authorization'][4:]).decode('ascii')))
			if session.HTTPAtuhentication._iterations == 0:
				session.HTTPAtuhentication._iterations = 1
				c = NTLMChallenge()
				c.construct()


				transport.write(HTTP401Resp(session, 'NTLM '+c.toBase64()).toBytes())
			elif session.HTTPAtuhentication._iterations == 1:
				session.HTTPAtuhentication._iterations = 2
				print('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB')
				print(req.headers['authorization'][5:])
				a = NTLMAuthenticateParser().parse(io.BytesIO(base64.b64decode(req.headers['authorization'][5:])))
				print(repr(a))
				print('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')


		else:
			print(HTTP401Resp(session, 'NTLM').toBytes())
			transport.write(HTTP401Resp(session, 'NTLM').toBytes())


class HTTPNTLMAuth():
	def __init__(self, creds = None):
		self._iterations = 0
		self.creds = creds

	def __repr__(self):
		t  = '== HTTPNTLMAuth ==\r\n'
		t += '_iterations: %s\r\n' % repr(self._iterations)
		t += 'creds:         %s\r\n' % repr(self.creds)
		return t


class NTLMAuthenticateParser():
	def parse(self, buff):
		auth = NTLMAuthenticate()
		auth.Signature    = buff.read(8).decode('ascii')
		auth.MessageType  = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		auth.LmChallengeResponseFields = FiledsParser().parse(buff)
		auth.NtChallengeResponseFields = FiledsParser().parse(buff)
		auth.DomainNameFields = FiledsParser().parse(buff)
		auth.UserNameFields = FiledsParser().parse(buff)
		auth.WorkstationFields = FiledsParser().parse(buff)
		auth.EncryptedRandomSessionKeyFields = FiledsParser().parse(buff)
		auth.NegotiateFlags = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		auth.Version = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		auth.MIC = int.from_bytes(buff.read(16), byteorder = 'little', signed = False)
		#auth.Payload = buff.read()

		##### MASSIVE BIG TODO!!!
		####here we shoudl decide which version of NTLM is used!!!!
		####Now I'm assuming ntlmv2
		####DID YOU JUST ASSUME MY AUTHENTICATION PROTOCOL VERSION???

		buff.seek(auth.LmChallengeResponseFields.offset,io.SEEK_SET)
		auth.LMChallenge = LMv2ResponseParser().parse(buff)
		
		buff.seek(auth.NtChallengeResponseFields.offset,io.SEEK_SET)
		auth.NTChallenge = NTLMv2ResponseParser().parse(buff)
		
		buff.seek(auth.DomainNameFields.offset,io.SEEK_SET)
		auth.DomainName = buff.read(auth.UserNameFields.length).decode('utf-16le')
		
		buff.seek(auth.UserNameFields.offset,io.SEEK_SET)
		auth.UserName = buff.read(auth.UserNameFields.length).decode('utf-16le')

		buff.seek(auth.WorkstationFields.offset,io.SEEK_SET)
		auth.Workstation = buff.read(auth.WorkstationFields.length).decode('utf-16le')

		buff.seek(auth.EncryptedRandomSessionKeyFields.offset,io.SEEK_SET)
		auth.EncryptedRandomSession = buff.read(auth.EncryptedRandomSessionKeyFields.length).decode('utf-16le')
		

		return auth

class NTLMAuthenticate():
	def __init__(self):
		self.Signature = None
		self.MessageType = None
		self.LmChallengeResponseFields = None
		self.NtChallengeResponseFields = None
		self.DomainNameFields = None
		self.UserNameFields = None
		self.WorkstationFields = None
		self.EncryptedRandomSessionKeyFields = None
		self.NegotiateFlags = None
		self.Version = None
		self.MIC = None
		self.Payload = None

		#high level
		self.LMChallenge = None
		self.NTChallenge = None
		self.DomainName = None
		self.UserName = None
		self.Workstation = None
		self.EncryptedRandomSession = None

	def __repr__(self):
		t  = '== NTLMAuthenticate =='
		t += 'Signature: %s\r\n' % repr(self.Signature)
		t += 'MessageType: %s\r\n' % repr(self.MessageType)
		t += 'NegotiateFlags: %s\r\n' % repr(self.NegotiateFlags)
		t += 'Version: %s\r\n' % repr(self.Version)
		t += 'MIC: %s\r\n' % repr(self.MIC)
		t += 'LMChallenge: %s\r\n' % repr(self.LMChallenge)
		t += 'NTChallenge: %s\r\n' % repr(self.NTChallenge)
		t += 'DomainName: %s\r\n' % repr(self.DomainName)
		t += 'UserName: %s\r\n' % repr(self.UserName)
		t += 'Workstation: %s\r\n' % repr(self.Workstation)
		t += 'EncryptedRandomSession: %s\r\n' % repr(self.EncryptedRandomSession)
		return t


#https://msdn.microsoft.com/en-us/library/cc236648.aspx
class LMResponseParser():
	def parse(self,buff):
		t = LMResponse()
		t.Response = buff.read(24).hex()
		return t

class LMResponse():
	def __init__(self):
		self.Response = None

	def __repr__(self):
		t  = '== LMResponse =='
		t += 'Response: %s' % repr(self.Response)
		return t

#https://msdn.microsoft.com/en-us/library/cc236649.aspx
class LMv2ResponseParser():
	def parse(self,buff):
		t = LMv2Response()
		t.Response = buff.read(16).hex()
		t.ChallengeFromClinet = buff.read(8).hex()
		return t

class LMv2Response():
	def __init__(self):
		self.Response = None
		self.ChallengeFromClinet = None

	def __repr__(self):
		t  = '== LMv2Response =='
		t += 'Response: %s' % repr(self.Response)
		t += 'ChallengeFromClinet: %s' % repr(self.ChallengeFromClinet)
		return t

#https://msdn.microsoft.com/en-us/library/cc236651.aspx
class NTLMv1ResponseParser():
	def parse(self,buff):
		t = NTLMv1Response()
		t.Response = buff.read(24).hex()
		return t

class NTLMv1Response():
	def __init__(self):
		self.Response = None

	def __repr__(self):
		t  = '== NTLMv1Response =='
		t += 'Response: %s' % repr(self.Response)
		return t

#https://msdn.microsoft.com/en-us/library/cc236653.aspx
class NTLMv2ResponseParser():
	def parse(self,buff):
		t = NTLMv2Response()
		t.Response = buff.read(16).hex()
		t.ChallengeFromClinet = NTLMv2ClientChallengeParser().parse(buff)
		return t

class NTLMv2Response():
	def __init__(self):
		self.Response = None
		self.ChallengeFromClinet = None

	def __repr__(self):
		t  = '== NTLMv2Response =='
		t += 'Response: %s' % repr(self.Response)
		t += 'ChallengeFromClinet: %s' % repr(self.ChallengeFromClinet)
		return t

class NTLMv2ClientChallengeParser():
	def __init__(self):
		pass
	
	def parse(self, buff):
		cc = NTLMv2ClientChallenge()
		cc.RespType   = int.from_bytes(buff.read(1), byteorder = 'little', signed = False)
		cc.HiRespType = int.from_bytes(buff.read(1), byteorder = 'little', signed = False)
		cc.Reserved1  = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		cc.Reserved2  = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		cc.TimeStamp  = timestamp2datetime(buff.read(8))
		cc.ChallengeFromClient = buff.read(8).hex()
		cc.Reserved3  = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		cc.Details    = AVPairsParser().parse(buff)

		return cc


class NTLMv2ClientChallenge():
	def __init__(self):
		self.RespType   = None
		self.HiRespType = None
		self.Reserved1  = None
		self.Reserved2  = None
		self.TimeStamp  = None
		self.ChallengeFromClient = None
		self.Reserved3  = None
		self.Reserved3  = None
		self.Details    = None #named AVPairs in the documentation

	def __repr__(self):
		t  = '== NTLMv2ClientChallenge =='
		t += 'RespType: %s' % repr(self.RespType)
		t += 'TimeStamp: %s' % repr(self.TimeStamp)
		t += 'ChallengeFromClient: %s' % repr(self.ChallengeFromClient)
		t += 'Details: %s' % repr(self.Details)
		return t



class NTLMChallenge():
	def __init__(self):
		self.Signature         = 'NTLMSSP\x00'
		self.MessageType       = 2
		self.TargetNameFields  = None
		self.NegotiateFlags    = None
		self.ServerChallenge   = None
		self.Reserved          = None
		self.TargetInfoFields  = None
		self.Version           = None
		self.Payload           = None

		self.TargetName        = None
		self.TargetInfo        = None

	def construct(self, challenge = os.urandom(8), targetName = None, targetInfo = None):
		self.NegotiateFlags    = int.from_bytes(b"\x05\x02\x89\xa2", byteorder = 'little', signed = False)
		self.Reserved          = int.from_bytes(b'\x00'*8, byteorder = 'little', signed = False)
		self.Version           = int.from_bytes(b"\x05\x02\xce\x0e\x00\x00\x00\x0f", byteorder = 'little', signed = False)
		self.ServerChallenge   = int.from_bytes(challenge, byteorder = 'little', signed = False)
		self.TargetName        = 'SMB'
		self.TargetInfo        = AVPairs({ AVPAIRType.MsvAvNbDomainName  : 'SMB',
									AVPAIRType.MsvAvNbComputerName       : 'SMB-TOOLKIT',
									AVPAIRType.MsvAvDnsDomainName        : 'smb.local',
									AVPAIRType.MsvAvDnsComputerName      : 'server2003.smb.local',
									AVPAIRType.MsvAvDnsTreeName          : 'smb.local',
						       })

		self.TargetNameFields = Fields(len(self.TargetName.encode('utf-16le')),56) 
		self.TargetInfoFields = Fields(len(self.TargetInfo.toBytes()), 56 + len(self.TargetName.encode('utf-16le')))

		self.Payload = self.TargetName.encode('utf-16le')
		self.Payload += self.TargetInfo.toBytes()

	def toBytes(self):
		tn = self.TargetName.encode('utf-16le')
		ti = self.TargetInfo.toBytes()

		buff  = self.Signature.encode('ascii')
		buff += self.MessageType.to_bytes(4, byteorder = 'little', signed = False)
		buff += self.TargetNameFields.toBytes()
		buff += self.NegotiateFlags.to_bytes(4, byteorder = 'little', signed = False)
		buff += self.ServerChallenge.to_bytes(8, byteorder = 'little', signed = False)
		buff += self.Reserved.to_bytes(8, byteorder = 'little', signed = False)
		buff += self.TargetInfoFields.toBytes()
		buff += self.Version.to_bytes(8, byteorder = 'little', signed = False)
		buff += self.Payload
		

		return buff 

	def toBase64(self):
		return base64.b64encode(self.toBytes()).decode('ascii')

class FiledsParser():
	def __init__(self):
		pass

	def parse(self, buff):
		length    = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		maxLength = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		offset    = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)

		return Fields(length, offset, maxLength = maxLength)

class Fields():
	def __init__(self, length, offset, maxLength = None):
		self.length = length
		self.maxLength = length if maxLength is None else maxLength
		self.offset = offset

	def toBytes(self):
		return  self.length.to_bytes(2, byteorder = 'little', signed = False) + \
				self.maxLength.to_bytes(2, byteorder = 'little', signed = False) + \
				self.offset.to_bytes(4, byteorder = 'little', signed = False)


class AVPairsParser():
	def __init__(self):
		pass

	def parse(self, buff):
		avp = AVPairs()
		while True:
			avId  = AVPAIRType(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
			AvLen = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
			if avId == AVPAIRType.MsvAvEOL:
				break

			elif avId in [AVPAIRType.MsvAvNbComputerName,
						  AVPAIRType.MsvAvNbDomainName,
						  AVPAIRType.MsvAvDnsComputerName,
						  AVPAIRType.MsvAvDnsDomainName,
						  AVPAIRType.MsvAvDnsTreeName,
						  AVPAIRType.MsvAvTargetName,
			]:
				avp[avId] = buff.read(AvLen).decode('utf-16le')

			### TODO IMPLEMENT PARSING OFR OTHER TYPES!!!!
			else:
				avp[avId] = buff.read(AvLen)

		return avp



#???? https://msdn.microsoft.com/en-us/library/windows/desktop/aa374793(v=vs.85).aspx
#https://msdn.microsoft.com/en-us/library/cc236646.aspx
class AVPairs(collections.UserDict):
	def __init__(self, data = None):
		collections.UserDict.__init__(self, data)

	def toBytes(self):
		t = b''
		for av in self.data:
			t += AVPair(data = self.data[av], type = av).toBytes()

		t+= AVPair(data = '', type = AVPAIRType.MsvAvEOL).toBytes()
		return t

class AVPair():
	def __init__(self, data = None, type = None):
		self.type = type
		self.data = data

	def toBytes(self):
		t  = self.type.value.to_bytes(2, byteorder = 'little', signed = False)
		t += len(self.data.encode('utf-16le')).to_bytes(2, byteorder = 'little', signed = False)
		t += self.data.encode('utf-16le')
		return t


class AVPAIRType(enum.Enum):
	MsvAvEOL             = 0x0000 #Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
	MsvAvNbComputerName  = 0x0001 #The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
	MsvAvNbDomainName    = 0x0002 #The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
	MsvAvDnsComputerName = 0x0003 #The fully qualified domain name (FQDN) of the computer. The name MUST be in Unicode, and is not null-terminated.
	MsvAvDnsDomainName   = 0x0004 #The FQDN of the domain. The name MUST be in Unicode, and is not null-terminated.
	MsvAvDnsTreeName     = 0x0005 #The FQDN of the forest. The name MUST be in Unicode, and is not null-terminated.<13>
	MsvAvFlags           = 0x0006 #A 32-bit value indicating server or client configuration.
	MsvAvTimestamp       = 0x0007 #A FILETIME structure ([MS-DTYP] section 2.3.3) in little-endian byte order that contains the server local time. This structure is always sent in the CHALLENGE_MESSAGE.<16>
	MsvAvSingleHost      = 0x0008 #A Single_Host_Data (section 2.2.2.2) structure. The Value field contains a platform-specific blob, as well as a MachineID created at computer startup to identify the calling machine.<17>
	MsvAvTargetName      = 0x0009 #The SPN of the target server. The name MUST be in Unicode and is not null-terminated.<18>
	MsvChannelBindings   = 0x000A #A channel bindings hash. The Value field contains an MD5 hash ([RFC4121] section 4.1.1.2) of a gss_channel_bindings_struct ([RFC2744] section 3.11). An all-zero value of the hash is used to indicate absence of channel bindings.<19>



class NTLMNegotiate():
	def __init__(self):
		self.Signature         = None
		self.MessageType       = None
		self.NegotiateFlags    = None
		self.DomainNameFields  = None
		self.WorkstationFields = None
		self.Version           = None
		self.Payload           = None

		####High-level variables
		self.Domain      = None
		self.Workstation = None

	def parse(self, buff):
		self.Signature      = buff.read(8).decode('ascii')
		self.MessageType    = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		self.NegotiateFlags = buff.read(4)
		self.DomainNameFields  = buff.read(8)
		self.WorkstationFields = buff.read(8)
		self.Version = buff.read(8)
		self.Payload = buff.read()

	def contrct(self):
		pass

class NEGOTIATEFlags(enum.IntEnum):
	pass
"""
	def RandomChallenge(self):
		if self.settings['NumChal'] == "random":
			from random import getrandbits
			NumChal = '%016x' % getrandbits(16 * 4)
			Challenge = b''
			for i in range(0, len(NumChal),2):
				Challenge += bytes.fromhex(NumChal[i:i+2])
			return Challenge
		else:
			return bytes.fromhex(self.settings['Challenge'])

class HTTPAuthorization():
	def __init__(self):
		self.type = ''
		self.data = ''

	def parse(self, t):
		marker = t.find(' ')
		if marker == -1:
			raise Exception('Header parsing error!' + repr(line))

		self.type = t[:marker]
		self.data = t[marker+1:]

	def toDict(self):
		t = {}
		t['type'] = self.type
		t['data'] = self.data
		return t



class HTTPRequest():
	def __init__(self):
		self.method = ''
		self.uri = ''
		self.version = ''
		self.headers = {}
		self.data = None

		self.authorization = None

		self.isWebDAV = False
		self.isFirefox = False
		self.isWpad = False

	def parse(self, data):
		self.rawdata = data
		header, self.data = self.rawdata.split('\r\n\r\n')

		request = ''
		first = True
		for line in header.split('\r\n'):
			if first:
				request = line
				first = False
				continue

			marker = line.find(':')
			if marker == -1:
				raise Exception('Header parsing error!' + repr(line))
			
			self.headers[line[:marker].strip().lower()] = line[marker+1:].strip()

		self.method, self.uri, self.version = request.split(' ')

		if self.uri.endswith('wpad.dat') or self.uri.endswith('.pac'):
			self.isWpad = True

		if self.method == 'PROPFIND':
			self.isWebDAV = True

		if 'user-agent' in self.headers:
			if self.headers['user-agent'].find('Firefox') != -1:
				self.isFirefox = True

		if 'authorization' in self.headers:
			self.authorization = HTTPAuthorization()
			self.authorization.parse(self.headers['authorization'])

class HTTPAuthorization():
	def __init__(self):
		self.type = ''
		self.data = ''

	def parse(self, t):
		marker = t.find(' ')
		if marker == -1:
			raise Exception('Header parsing error!' + repr(line))

		self.type = t[:marker]
		self.data = t[marker+1:]

	def toDict(self):
		t = {}
		t['type'] = self.type
		t['data'] = self.data
		return t

"""