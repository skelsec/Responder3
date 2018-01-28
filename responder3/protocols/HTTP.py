import io
import os
import enum
import zlib
import base64
from responder3.protocols.NTLM import NTLMAUTHHandler, NTLMAuthStatus

class HTTPVersion(enum.Enum):
	HTTP10 = 'HTTP/1.0'
	HTTP11 = 'HTTP/1.1'

class HTTPState(enum.Enum):
	UNAUTHENTICATED = enum.auto()
	AUTHENTICATED   = enum.auto()
	AUTHFAILED      = enum.auto()

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
	409 : 'Conflict',
	410 : 'Gone',
	411 : 'Length Required',
	412 : 'Precondition Failed',
	413 : 'Request Entity Too Large',
	414 : 'Request-URI Too Large',
	415 : 'Unsupported Media Type',
	416 : 'Requested range not satisfiable',
	417 : 'Expectation Failed',
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
		self.headers = {
			'Content-Type'  : 'text/html',
			'Content-Length': 0,
		}

	def toBytes(self):
		####################################
		####################################
		## TODO!!! use specific encoding + compression when needed!!!

		#calculating body by applying sepcific ancoding and compression
		t_body = ''
		if self.body is not None:
			t_body = self.body

		#updating content-length field
		self.headers['Content-Length'] = str(len(t_body))


		t  = '%s %s %s\r\n' % (self.version, self.code, self.reason)
		for key, value in self.headers.items():
			t += key + ': ' + self.headers[key] + '\r\n'
		t += '\r\n'
		t = t.encode('ascii')

		if self.body is not None:
			t += t_body.encode('utf-8')
		
		return t



class HTTP200Resp(HTTPResponseBase):
	def __init__(self, session, body = None):
		HTTPResponseBase.__init__(self, session, 200, body = body)


class HTTP301Resp(HTTPResponseBase):
	def __init__(self, redirectURL):
		HTTPResponseBase.__init__(self, session, 301)
		self.headers['Location'] = redirectURL

class HTTP400Resp(HTTPResponseBase):
	def __init__(self, session, body = None):
		HTTPResponseBase.__init__(self, session, 400, body = body)

class HTTP401Resp(HTTPResponseBase):
	def __init__(self, session, authType, authChallenge = None, body = None, isProxy = False):
		HTTPResponseBase.__init__(self, session, 401, body = body)
		if isProxy:
			if authChallenge is not None:
				self.headers['Proxy-Authenticate'] = '%s %s' % (authType, authChallenge)
			else:
				self.headers['Proxy-Authenticate'] = '%s' % authType
		else:
			if authChallenge is not None:
				self.headers['WWW-Authenticate'] = '%s %s' % (authType, authChallenge)
			else:
				self.headers['WWW-Authenticate'] = '%s' % authType

class HTTP403Resp(HTTPResponseBase):
	def __init__(self, session, authType, authChallenge = None, body = None):
		HTTPResponseBase.__init__(self, session, 403, body = body)

class HTTPBasicAuth():
	"""
	Handling HTTP basic Auth
	verifyCreds: can be a  1. dictionary with user:password pairs.
						 2. empty dict means nobody is allowed
						 3. None means EVERYBODY IS ALLOWED
	"""

	def __init__(self, verifyCreds = None, isProxy = False):
		self._iterations = 0
		self.isProxy = isProxy
		self.verifyCreds = verifyCreds
		self.userCreds   = None


	def do_AUTH(self, httpReq, transport, session):
		authHdr = 'authorization'
		if self.isProxy:
			authHdr = 'proxy-authorization'
		
		if authHdr in httpReq.headers and httpReq.headers[authHdr][:5].upper() == 'BASIC':
			#print('Authdata in! %s' % (base64.b64decode(httpReq.headers['authorization'][5:]).decode('ascii')))
			temp = base64.b64decode(httpReq.headers[authHdr][5:]).decode('ascii')
			marker = temp.find(':')
			self.userCreds   = BASICUserCredentials()
			self.userCreds.username = temp[:marker]
			self.userCreds.password = temp[marker+1:]

			#print(self.userCreds.username)
			#print(self.userCreds.password)

			if self.verify():
				session.currentState = HTTPState.AUTHENTICATED
			else:
				session.currentState = HTTPState.AUTHFAILED

			return self.userCreds

		else:
			transport.write(HTTP401Resp(session, 'Basic', isProxy = self.isProxy).toBytes())
			transport.close()

	def verify(self):
		if self.verifyCreds is None:
			return True
		else:
			if self.userCreds.username in self.verifyCreds:
				return self.verifyCreds[self.userCreds.username] == self.userCreds.password
			else:
				return False
		return False

class BASICUserCredentials():
	def __init__(self):
		self.username = None
		self.password = None

	def toResult(self):
		res = {
			'type'     : 'Cleartext', 
			'user'     : self.username,
			'cleartext': self.password, 
			'fullhash' : '%s:%s' % (self.username, self.password)
		}
		return res

class HTTPNTLMAuth():
	def __init__(self, verifyCreds = None, isProxy = False):
		self.isProxy = isProxy
		self.hander = NTLMAUTHHandler()
		self.verifyCreds = verifyCreds
		self.settings = None
		self.status = 0

	def setup(self, settings = {}):
		#settings here
		self.hander.setup(settings)
		return


	def do_AUTH(self, httpRequest, transport, session):
		authHdr = 'authorization'
		if self.isProxy:
			authHdr = 'proxy-authorization'

		if authHdr in httpRequest.headers and httpRequest.headers[authHdr][:4].upper() == 'NTLM':
			authStatus, ntlmMessage, creds = self.hander.do_AUTH(base64.b64decode(httpRequest.headers[authHdr][5:]))
			if self.status == 0 and authStatus == NTLMAuthStatus.FAIL:
				self.status += 1
				transport.write(HTTP401Resp(session, 'NTLM '+ base64.b64encode(ntlmMessage).decode('ascii'), isProxy = self.isProxy).toBytes())
				return
			
			elif self.status == 1 and authStatus == NTLMAuthStatus.FAIL:
				session.currentState = HTTPState.AUTHFAILED
				return creds

			elif self.status == 1 and authStatus == NTLMAuthStatus.OK:
				session.currentState = HTTPState.AUTHENTICATED
				return creds

			else:
				raise Exception('Unexpected status')
		else:
			transport.write(HTTP401Resp(session, 'NTLM').toBytes())


"""
	def HTTPNTLMAuthHandler(req, transport, session):
		if 'authorization' in req.headers and req.headers['authorization'][:4] == 'NTLM':
			#print('Authdata in! %s' % (base64.b64decode(req.headers['authorization'][4:]).decode('ascii')))
			if session.HTTPAtuhentication._iterations == 0:
				session.HTTPAtuhentication._iterations = 1
				c = NTLMChallenge.construct_from_template('Windows2003')
				session.HTTPAtuhentication.ServerChallenge = c.ServerChallenge
				transport.write(HTTP401Resp(session, 'NTLM '+c.toBase64()).toBytes())
			
			elif session.HTTPAtuhentication._iterations == 1:
				session.HTTPAtuhentication._iterations = 2
				print(req.headers['authorization'][5:])
				a = NTLMAuthenticate.from_bytes(base64.b64decode(req.headers['authorization'][5:]))
				print(repr(a))

				#THIS IS TERRIBLE!!!! TODODODODODODODODODODOD!!!!
				#we'd need to check what authentication method is used exacly (choices: NTLMv1 NTLMv1extended NTLMv2)
				if len(a.NTBytes) == 24:
					print('%s::%s:%s:%s:%s' % (a.UserName, a.Workstation, a.LMBytes.hex(), a.NTBytes.hex(), session.HTTPAtuhentication.ServerChallenge))

				else:
					print('%s::%s:%s:%s:%s' % (a.UserName, a.DomainName, session.HTTPAtuhentication.ServerChallenge, a.NTBytes.hex()[:32], a.NTBytes.hex()[32:]))

				
				#'%s::%s:%s:%s:%s' % (User, Domain, settings.Config.NumChal, NTHash[:32], NTHash[32:])
				#'%s::%s:%s:%s:%s' % (User, HostName, LMHash, NTHash, settings.Config.NumChal)

				
			elif session.HTTPAtuhentication._iterations == 2:
				raise Exception('unexpected iter')


		else:
			print(HTTP401Resp(session, 'NTLM').toBytes())
			transport.write(HTTP401Resp(session, 'NTLM').toBytes())




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