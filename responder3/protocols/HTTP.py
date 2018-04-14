import io
import os
import enum
import zlib
import gzip
import base64
import asyncio
import collections

from responder3.core.commons import *
from responder3.protocols.NTLM import NTLMAUTHHandler
from responder3.protocols.SMB.ntstatus import *

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

def decompress_body(req_resp, modify_internal = False):
	if req_resp.headers[req_resp.cenc] == HTTPContentEncoding.IDENTITY:
		if modify_internal:
			req_resp.body = req_resp.body
		else:
			return req_resp.body
	elif req_resp.headers[req_resp.cenc] == HTTPContentEncoding.GZIP:
		if modify_internal:
			req_resp.body = gzip.decompress(req_resp.body)
		else:
			return gzip.decompress(req_resp.body)

		#self.httprequest.body = zlib.decompress(body, 16+zlib.MAX_WBITS)

	elif req_resp.headers[req_resp.cenc] == HTTPContentEncoding.COMPRESS:
		raise Exception('Not Implemented!')

	elif req_resp.headers[req_resp.cenc] == HTTPContentEncoding.DEFLATE:
		if modify_internal:
			req_resp.body = zlib.decompress(req_resp.body)
		else:
			return zlib.decompress(req_resp.body)
		
	elif req_resp.headers[req_resp.cenc] == HTTPContentEncoding.BR:
		raise Exception('Not Implemented!')
	else:
		raise Exception('Encoding format not recognized!')
		

def compress_body(req_resp, modify_internal = False):
	if req_resp.cenc is not None:
		if req_resp.headers[req_resp.cenc] == HTTPContentEncoding.IDENTITY:
			if modify_internal:
				req_resp.body = req_resp.body
			else:
				return req_resp.body.encode()
			
		elif req_resp.headers[req_resp.cenc] == HTTPContentEncoding.GZIP:
			if modify_internal:
				req_resp.body = gzip.compress(req_resp.body)
			else:
				return gzip.compress(req_resp.body,  compresslevel=1)

		elif req_resp.headers[req_resp.cenc] == HTTPContentEncoding.COMPRESS:
			raise Exception('COMPRESS Not Implemented!')

		elif req_resp.headers[req_resp.cenc] == HTTPContentEncoding.DEFLATE:
			if modify_internal:
				req_resp.body = zlib.compress(req_resp.body)
			else:
				return zlib.compress(req_resp.body)

		elif req_resp.headers[req_resp.cenc] == HTTPContentEncoding.BR:
			raise Exception('BR Not Implemented!')
		else:
			raise Exception('Encoding format not recognized!')

	else:
		if modify_internal:
			req_resp.body = req_resp.body.encode()
		else:
			return req_resp.body.encode()
	

class HTTPRequest():
	def __init__(self):
		self.method  = None
		self.uri     = None
		self.version = None
		self.headers = collections.OrderedDict()
		self.body    = None

		#helper variables
		self.clen = None
		self.cenc = None
		self.ccon = None

	def construct(method, uri, headers, body = None, version = HTTPVersion.HTTP11):
		req = HTTPRequest()
		req.method = method
		req.uri = uri
		req.version = version
		req.headers = headers
		req.body = body #this will be bytes!
		return req

	def toBytes(self):
		for hdr in self.headers:
			if hdr.lower() == 'content-encoding':
				self.cenc = hdr
			elif hdr.lower() == 'content-length':
				self.clen = hdr

		if self.clen is None:
			self.clen = 'Content-Length'

		t_body = self.body
		if self.body is not None:
			if self.cenc in self.headers:
				t_body = compress_body(self)
			else:
				t_body = self.body
			self.headers[self.clen] = int(len(t_body))

		t = '%s %s %s%s' % (self.method, self.uri, self.version.value, '\r\n')
		for hdr in self.headers:
			t+= '%s: %s\r\n' % (hdr, self.headers[hdr])

		t+= '\r\n'
		t = t.encode('ascii')
		#now to deal with the body
		if self.body is not None:
			t+= t_body
		return t
		
	@asyncio.coroutine
	def from_streamreader(reader, timeout = None):
		try:
			req = HTTPRequest()
			firstline = yield from readline_or_exc(reader, timeout = timeout)
			try:
				req.method, req.uri, t = firstline.decode('ascii').strip().split(' ')
				req.version = HTTPVersion(t.upper())
			except Exception as e:
				raise e

			hdrs = yield from readuntil_or_exc(reader, b'\r\n\r\n', timeout = timeout)
			hdrs = hdrs[:-4].decode('ascii').split('\r\n')
			for hdr in hdrs:
				marker = hdr.find(': ')
				key   = hdr[:marker]
				value = hdr[marker+2:]
				if key.lower() == 'content-encoding':
					#TODO
					#THIS DOESNT TAKE MULTIPLE-TYPE COMPRESSION INTO ACCOUNT AND WILL FAIL!
					req.headers[key] = HTTPContentEncoding[value.upper()]
					req.cenc = key
				elif key.lower() == 'content-length':
					req.headers[key] = int(value)
					req.clen = key

				elif key.lower() == 'connection':
					req.headers[key] = value
					req.ccon = key
				
				else:
					req.headers[key] = value

			#this 'guessing' is needed to keep the original header names, you never know what might crash
			if req.clen is None or req.headers[req.clen] == 0:
				#at this point the request did not have a content-length field
				return req

			else:
				req.body = yield from read_or_exc(reader, int(req.headers[req.clen]), timeout = timeout)
				if req.cenc is not None:
					decompress_body(req, modify_internal=True)
			return req


		except Exception as e:
			if isinstance(e, ConnectionClosed):
				return
			raise e


	def from_bytes(bbuff):
		HTTPRequest.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		#not tested, the actively used code is in from_streamreader!!!
		req = HTTPRequest()
		req.method, req.uri, t = buff.readline().strip().decode('ascii').split(b' ')
		req.version = HTTPVersion(t.upper())
		
		#end = False
		while True:
			hdr = buff.readline().strip().decode('ascii')
			if hdr == '':
				hdr = buff.readline().strip().decode('ascii')
				if hdr == '':
					break
				else:
					raise Exception('Empty header')

			marker = hdr.find(': ')
			key   = hdr[:marker]
			value = hdr[marker+2:]
			if key.lower() == 'content-encoding':
				#TODO
				#THIS DOESNT TAKE MULTIPLE-TYPE COMPRESSION INTO ACCOUNT AND WILL FAIL!
				req.headers[key] = HTTPContentEncoding[value.upper()]
				req.cenc = key
			elif key.lower() == 'content-length':
				req.headers[key] = int(value)
				req.clen = key

			elif key.lower() == 'connection':
					req.headers[key] = value
					req.ccon = key
				
			
			else:
				req.headers[key] = value

		#this 'guessing' is needed to keep the original header names
		if req.clen is None or req.headers[req.clen] == 0:
			#at this point the request did not have a content-length field
			return req

		else:
			req.body = yield from reader.read(int(req.headers[req.clen]))
			if req.cenc is not None:
				decompress_body(req, modify_internal=True)
		return req

	def __repr__(self):
		t  = '== HTTP Request ==\r\n'
		t += 'FIRST  : %s\r\n' %' '.join([self.method, self.uri, self.version.value])
		t += 'HEADERS: %s\r\n' % repr(self.headers)
		t += 'BODY   : \r\n %s\r\n' % repr(self.body)
		return t

class HTTPResponse():
	def __init__(self):
		self.version = None
		self.code    = None
		self.reason  = None
		self.body    = None
		self.headers = None

		#helper variables
		self.clen = None
		self.cenc = None
		self.ccon = None

	@asyncio.coroutine
	def from_streamreader(reader, timeout = None):
		resp = HTTPResponse()
		t = yield from readuntil_or_exc(reader, b' ', timeout = timeout)
		resp.version = HTTPVersion(t.decode().upper().strip())
		t = yield from readuntil_or_exc(reader, b' ', timeout = timeout)
		resp.code = int(t.decode().strip())
		t = yield from readline_or_exc(reader, timeout = timeout)
		resp.reason = t.decode().strip()

		resp.headers = collections.OrderedDict()
		hdrs = yield from reader.readuntil(b'\r\n\r\n', timeout = timeout)
		hdrs = hdrs[:-4].decode('ascii').split('\r\n')
		for hdr in hdrs:
			marker = hdr.find(': ')
			key   = hdr[:marker]
			value = hdr[marker+2:]
			if key.lower() == 'content-encoding':
				#TODO
				#THIS DOESNT TAKE MULTIPLE-TYPE COMPRESSION INTO ACCOUNT AND WILL FAIL!
				resp.headers[key] = HTTPContentEncoding[value.upper()]
				resp.cenc = key
			elif key.lower() == 'content-length':
				resp.headers[key] = int(value)
				resp.clen = key
			elif key.lower() == 'connection':
				resp.headers[key] = value
				resp.ccon = key
			
			else:
				resp.headers[key] = value

		#this 'guessing' is needed to keep the original header names
		if resp.clen is None or resp.headers[resp.clen] == 0:
			#at this point the request did not have a content-length field
			return resp

		else:
			resp.body = yield from reader.read(int(resp.headers[resp.clen]), timeout = timeout)
			if resp.cenc is not None:
				decompress_body(resp, modify_internal=True)
		return resp

	def from_bytes(bbuff):
		return HTTPResponse.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		resp = HTTPResponse()
		firstline = buff.readline().decode().strip()
		m = firstline.find(' ')
		assert m != -1
		resp.version = HTTPVersion(firstline[:m].strip())
		firstline = firstline[m+1:]
		m = firstline.find(' ')
		assert m != -1
		resp.code = int(firstline[:m].strip())
		resp.reason = firstline[m+1:].strip()

		resp.headers = collections.OrderedDict()
		
		while True:
			hdrline = buff.readline().decode('ascii').strip()
			if hdrline == '':
				break
			marker = hdrline.find(': ')
			key   = hdrline[:marker]
			value = hdrline[marker+2:]
			if key.lower() == 'content-encoding':
				#TODO
				#THIS DOESNT TAKE MULTIPLE-TYPE COMPRESSION INTO ACCOUNT AND WILL FAIL!
				resp.headers[key] = HTTPContentEncoding[value.upper()]
				resp.cenc = key
			elif key.lower() == 'content-length':
				resp.headers[key] = int(value)
				resp.clen = key
			
			else:
				resp.headers[key] = value
			

		#this 'guessing' is needed to keep the original header names
		if resp.clen is None or resp.headers[resp.clen] == 0:
			#at this point the request did not have a content-length field
			return resp

		else:
			resp.body = buff.read(int(resp.headers[resp.clen]))
			if resp.cenc is not None:
				decompress_body(resp, modify_internal=True)
		return resp

	def __repr__(self):
		t  = '== HTTPResponse ==\r\n'
		t += 'version: %s \r\n' % self.version.value
		t += 'code: %s \r\n' % self.code
		t += 'reason: %s \r\n' % self.reason
		t += 'headers: %s \r\n' % self.headers
		t += 'body: %s \r\n' % repr(self.body)
		return t


	def __str__(self):
		return self.__repr__()

	def construct(code, body = None, httpversion = HTTPVersion.HTTP11, headers = collections.OrderedDict(), reason = None):
		resp = HTTPResponse()
		resp.version = httpversion
		resp.code    = int(code)
		if reason is None:
			resp.reason = HTTPResponseReasons[code] if code in HTTPResponseReasons else 'Pink kittens'
		else:
			resp.reason = reason
		
		resp.body    = body
		resp.headers = headers

		return resp
		
		"""
		'Content-Type'  : 'text/html',
					'Content-Length': 0,
				}
		"""

	def toBytes(self):
		####################################
		####################################
		## TODO!!! use specific encoding + compression when needed!!!

		#calculating body by applying sepcific ancoding and compression
		self.code    = int(self.code)
		t_body = None
		if self.body is not None and self.body != '':
			t_body = compress_body(self)

		#updating content-length field
		if t_body is None:
			self.headers['Content-Length'] = '0'
		else:
			self.headers['Content-Length'] = str(len(t_body))

		
		if self.reason is None:
			self.reason = HTTPResponseReasons[self.code] if self.code in HTTPResponseReasons else 'Pink kittens'


		t  = '%s %s %s\r\n' % (self.version.value, self.code, self.reason)
		for key, value in self.headers.items():
			if isinstance(value,enum.Enum):
				t += '%s: %s\r\n' % (key,self.headers[key].name.lower())
			else:
				t += '%s: %s\r\n' % (key,self.headers[key])
		t += '\r\n'
		t = t.encode('ascii')

		if t_body is not None:
			t += t_body
		
		return t



class HTTP200Resp(HTTPResponse):
	def __init__(self, body = None, httpversion = HTTPVersion.HTTP11, 
						headers = collections.OrderedDict(), reason = None):
		HTTPResponse.__init__(self)
		self.version = httpversion
		self.code    = '200'
		self.reason  = reason
		self.body    = body
		self.headers = headers

class HTTP301Resp(HTTPResponse):
	def __init__(self,redirectURL, body = None, httpversion = HTTPVersion.HTTP11, 
						headers = collections.OrderedDict(), reason = None):
		HTTPResponse.__init__(self)
		self.version = httpversion
		self.code    = '301'
		self.reason  = reason
		self.body    = body
		self.headers = collections.OrderedDict()
		self.headers['Location'] = redirectURL

class HTTP400Resp(HTTPResponse):
	def __init__(self, body = None, httpversion = HTTPVersion.HTTP11, 
						headers = collections.OrderedDict(), reason = None):
		HTTPResponse.__init__(self)
		self.version = httpversion
		self.code    = '400'
		self.reason  = reason
		self.body    = body
		self.headers = headers

class HTTP401Resp(HTTPResponse):
	def __init__(self, authType,authChallenge = None, body = None, 
						httpversion = HTTPVersion.HTTP11, 
						headers = collections.OrderedDict(), reason = None):
		HTTPResponse.__init__(self)
		self.version = httpversion
		self.code    = '401'
		self.reason  = reason
		self.body    = body
		self.headers = headers

		if authChallenge is not None:
			self.headers['WWW-Authenticate'] = '%s %s' % (authType, authChallenge)
		else:
			self.headers['WWW-Authenticate'] = '%s' % authType

class HTTP403Resp(HTTPResponse):
	def __init__(self, body = None, httpversion = HTTPVersion.HTTP11, 
						headers = collections.OrderedDict(), reason = None):
		HTTPResponse.__init__(self)
		self.version = httpversion
		self.code    = '403'
		self.reason  = reason
		self.body    = body
		self.headers = headers

class HTTP407Resp(HTTPResponse):
	def __init__(self, authType,authChallenge = None, body = None, httpversion = HTTPVersion.HTTP11, 
						headers = collections.OrderedDict(), reason = None):
		HTTPResponse.__init__(self)
		self.version = httpversion
		self.code    = '407'
		self.reason  = reason
		self.body    = body
		self.headers = headers

		if authChallenge is not None:
			self.headers['Proxy-Authenticate'] = '%s %s' % (authType, authChallenge)
		else:
			self.headers['Proxy-Authenticate'] = '%s' % authType


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

	@asyncio.coroutine
	def do_AUTH(self, httpReq, httpserver):
		authHdr = 'Authorization'
		if self.isProxy:
			authHdr = 'Proxy-Authorization'
		
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
				httpserver.session.currentState = HTTPState.AUTHENTICATED
			else:
				httpserver.session.currentState = HTTPState.AUTHFAILED

			httpserver.log_credential(self.userCreds.toCredential())

		else:
			if self.isProxy:
				a = yield from asyncio.wait_for(httpserver.send_data(HTTP407Resp('Basic').toBytes()), timeout = 1)
			else:
				a = yield from asyncio.wait_for(httpserver.send_data(HTTP401Resp('Basic').toBytes()), timeout = 1)
			return

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

	def toCredential(self):
		cred = Credential('Cleartext',
							username = self.username, 
							password = self.password, 
							fullhash = '%s:%s' % (self.username, self.password)
						)
		return cred

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

	@asyncio.coroutine
	def do_AUTH(self, httpRequest, httpserver):
		authHdr = 'Authorization'
		if self.isProxy:
			authHdr = 'Proxy-Authorization'

		if authHdr in httpRequest.headers and httpRequest.headers[authHdr][:4].upper() == 'NTLM':
			authStatus, ntlmMessage, creds = self.hander.do_AUTH(base64.b64decode(httpRequest.headers[authHdr][5:]))
			if self.status == 0 and authStatus == NTStatus.STATUS_MORE_PROCESSING_REQUIRED:
				self.status += 1
				if self.isProxy:
					a = yield from asyncio.wait_for(httpserver.send_data(HTTP407Resp('NTLM '+ base64.b64encode(ntlmMessage).decode('ascii')).toBytes()), timeout =1 )
				else:
					a = yield from asyncio.wait_for(httpserver.send_data(HTTP401Resp('NTLM '+ base64.b64encode(ntlmMessage).decode('ascii')).toBytes()), timeout =1 )
				return
			
			elif self.status == 1 and authStatus == NTStatus.STATUS_ACCOUNT_DISABLED:
				#### TODO!!!! When NTLM credential verification is implemented, uncomment the lines below!!!
				#### and comment out the auth successful line!
				#httpserver.session.currentState = HTTPState.AUTHFAILED
				#for cred in creds:
				#	httpserver.log_credential(cred.toCredential())
				httpserver.session.currentState = HTTPState.AUTHENTICATED

			elif self.status == 1 and authStatus == NTStatus.STATUS_SUCCESS:
				httpserver.session.currentState = HTTPState.AUTHENTICATED
				for cred in creds:
					httpserver.log_credential(cred.toCredential())

			else:
				raise Exception('Unexpected status')
		else:
			if self.isProxy:
				a = yield from asyncio.wait_for(httpserver.send_data(HTTP407Resp('NTLM').toBytes()), timeout = 1)
			else:
				a = yield from asyncio.wait_for(httpserver.send_data(HTTP401Resp('NTLM').toBytes()), timeout = 1)
			return