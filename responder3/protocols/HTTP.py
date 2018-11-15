import io
import os
import enum
import zlib
import gzip
import base64
import asyncio
import collections

from responder3.core.commons import *
from responder3.core.logging.log_objects import Credential
from responder3.core.asyncio_helpers import *
from responder3.protocols.NTLM import NTLMAUTHHandler
from responder3.protocols.SMB.ntstatus import *


class HTTPConnection(enum.Enum):
	CLOSE = 'close'
	KEEP_ALIVE = 'keep-alive'


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
	tbuff = None
	if req_resp.props.content_encoding == HTTPContentEncoding.IDENTITY:
		tbuff = req_resp.body

	elif req_resp.props.content_encoding == HTTPContentEncoding.GZIP:
		tbuff = gzip.decompress(req_resp.body)

	elif req_resp.props.content_encoding == HTTPContentEncoding.COMPRESS:
		raise Exception('Not Implemented!')

	elif req_resp.props.content_encoding == HTTPContentEncoding.DEFLATE:
		tbuff = zlib.decompress(req_resp.body)
		
	elif req_resp.props.content_encoding == HTTPContentEncoding.BR:
		raise Exception('Not Implemented!')

	else:
		raise Exception('Encoding format not recognized!')

	if modify_internal:
		req_resp.body = tbuff
	else:
		return tbuff

def compress_body(req_resp, modify_internal = False):
	tbuff = None
	if req_resp.props.content_encoding is not None:
		if req_resp.props.content_encoding == HTTPContentEncoding.IDENTITY:
			tbuff = req_resp.body
			
		elif req_resp.props.content_encoding == HTTPContentEncoding.GZIP:
			tbuff = gzip.compress(req_resp.body)

		elif req_resp.props.content_encoding == HTTPContentEncoding.COMPRESS:
			raise Exception('COMPRESS Not Implemented!')

		elif req_resp.props.content_encoding == HTTPContentEncoding.DEFLATE:
			tbuff = zlib.compress(req_resp.body)

		elif req_resp.props.content_encoding == HTTPContentEncoding.BR:
			raise Exception('BR Not Implemented!')
		else:
			raise Exception('Encoding format not recognized!')

	else:
		tbuff = req_resp.body

	if modify_internal:
		req_resp.body = tbuff
	else:
		return tbuff


class HTTPRequestProps:
	def __init__(self):
		self.content_length = None
		self.content_encoding = None
		self.connection = None
		self.encoding = None
		self.compression = None

	@staticmethod
	def from_request(req):
		p = HTTPRequestProps()
		for key in req.headers:
			if key.lower() == 'content-encoding':
				# TODO: THIS DOESNT TAKE MULTIPLE-TYPE COMPRESSION INTO ACCOUNT AND WILL FAIL!
				p.content_encoding = HTTPContentEncoding[req.headers[key].upper()]
			elif key.lower() == 'content-length':
				p.content_length = int(req.headers[key])

			elif key.lower() == 'connection':
				try:
					p.connection = HTTPConnection(req.headers[key].lower())
				except:
					p.connection = HTTPConnection.KEEP_ALIVE
		return p


class HTTPRequest:
	def __init__(self):
		self.method  = None
		self.uri     = None
		self.version = None
		self.headers = collections.OrderedDict()
		self.body    = None

		# helper variables
		self.header_key_lookup_table = {}
		self.props = None

	def construct(method, uri, headers, body = None, version = HTTPVersion.HTTP11):
		req = HTTPRequest()
		req.method = method
		req.uri = uri
		req.version = version
		req.headers = headers
		req.body = body # this will be bytes!
		req.props = HTTPRequestProps.from_request(req)
		return req

	def get_header(self, key):
		"""
		Function to map canonized header names (all lower) to the original header key values as they were recieved
		:param key: header key to lookup
		:return: header value or None
		"""
		if key.lower() not in self.header_key_lookup_table:
			return None
		original_key = self.header_key_lookup_table[key.lower()]
		return self.headers[original_key]

	def update_header(self, key, value):
		if key.lower() not in self.header_key_lookup_table:
			self.headers[key] = value
		else:
			self.headers[self.header_key_lookup_table[key.lower()]] = value
		self.props = HTTPRequestProps.from_request(self)

	def remove_header(self, key):
		if key.lower() not in self.header_key_lookup_table:
			return
		original_key = self.header_key_lookup_table[key.lower()]
		if original_key is None:
			return
		del self.headers[original_key]
		del self.header_key_lookup_table[key.lower()]
		return

	def to_bytes(self):
		if self.props is None:
			self.props = HTTPRequestProps.from_request(self)

		if self.props.content_length is None:
			self.update_header('Content-Length', 0)

		t_body = self.body
		if self.body is not None:
			if self.props.content_encoding is not None:
				t_body = compress_body(self)
			else:
				t_body = self.body
			self.update_header('Content-Length', int(len(t_body)))

		t = '%s %s %s%s' % (self.method, self.uri, self.version.value, '\r\n')
		for hdr in self.headers:
			t += '%s: %s\r\n' % (hdr, self.headers[hdr])

		t += '\r\n'
		t = t.encode('ascii')
		# now to deal with the body
		if self.body is not None:
			t += t_body
		return t

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		try:
			req = HTTPRequest()
			firstline = await readline_or_exc(reader, timeout = timeout)
			try:
				req.method, req.uri, t = firstline.decode('ascii').strip().split(' ')
				req.version = HTTPVersion(t.upper())
			except Exception as e:
				raise e

			hdrs = await readuntil_or_exc(reader, b'\r\n\r\n', timeout = timeout)
			hdrs = hdrs[:-4].decode('ascii').split('\r\n')
			for hdr in hdrs:
				marker = hdr.find(': ')
				key   = hdr[:marker]
				value = hdr[marker+2:]
				req.header_key_lookup_table[key.lower()] = key
				req.headers[key] = value

			req.props = HTTPRequestProps.from_request(req)

			if req.props.content_length is None or req.props.content_length == 0:
				return req

			else:
				req.body = await read_or_exc(reader, req.props.content_length, timeout = timeout)
				if req.props.content_encoding is not None:
					decompress_body(req, modify_internal=True)
			return req

		except Exception as e:
			if isinstance(e, ConnectionClosed):
				return
			raise e

	@staticmethod
	def from_bytes(bbuff):
		pass
		# TODO: whn everything looks nice, implement buffer parsing
		# HTTPRequest.from_buffer(io.BytesIO(bbuff))

	def __repr__(self):
		t  = '== HTTP Request ==\r\n'
		t += 'FIRST  : %s\r\n' %' '.join([self.method, self.uri, self.version.value])
		t += 'HEADERS: %s\r\n' % repr(self.headers)
		t += 'BODY   : \r\n %s\r\n' % repr(self.body)
		return t


class HTTPResponse:
	def __init__(self):
		self.version = None
		self.code    = None
		self.reason  = None
		self.body    = None
		self.headers = collections.OrderedDict()

		# helper variables
		self.header_key_lookup_table = {}
		self.props = None

	def get_header(self, key):
		"""
		Function to map canonized header names (all lower) to the original header key values as they were recieved
		:param key: header key to lookup
		:return: header value or None
		"""
		if key.lower() not in self.header_key_lookup_table:
			return None
		original_key = self.header_key_lookup_table[key.lower()]
		return self.headers[original_key]

	def update_header(self, key, value):
		if key.lower() not in self.header_key_lookup_table:
			self.headers[key] = value
		else:
			self.headers[self.header_key_lookup_table[key.lower()]] = value
		self.props = HTTPRequestProps.from_request(self)

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		resp = HTTPResponse()
		t = await readuntil_or_exc(reader, b' ', timeout = timeout)
		resp.version = HTTPVersion(t.decode().upper().strip())
		t = await readuntil_or_exc(reader, b' ', timeout = timeout)
		resp.code = int(t.decode().strip())
		t = await readline_or_exc(reader, timeout = timeout)
		resp.reason = t.decode().strip()

		hdrs = await readuntil_or_exc(reader, b'\r\n\r\n', timeout=timeout)
		hdrs = hdrs[:-4].decode('ascii').split('\r\n')
		for hdr in hdrs:
			marker = hdr.find(': ')
			key = hdr[:marker]
			value = hdr[marker + 2:]
			resp.header_key_lookup_table[key.lower()] = key
			resp.headers[key] = value

		resp.props = HTTPRequestProps.from_request(resp)

		if resp.props.content_length is None or resp.props.content_length == 0:
			return resp

		else:
			resp.body = await read_or_exc(reader, resp.props.content_length, timeout=timeout)
			if resp.props.content_encoding is not None:
				decompress_body(resp, modify_internal=True)
		return resp

	@staticmethod
	def from_bytes(bbuff):
		pass
		# TODO: implement buffer parsing when everything looks nice
		# return HTTPResponse.from_buffer(io.BytesIO(bbuff))

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

	@staticmethod
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

	def to_bytes(self):
		if self.props is None:
			self.props = HTTPRequestProps.from_request(self)

		if self.props.content_length is None:
			self.update_header('Content-Length', 0)

		t_body = b''
		if self.body is not None:
			if self.props.content_encoding is not None:
				t_body = compress_body(self)
			else:
				t_body = self.body.encode()
			self.update_header('Content-Length', int(len(t_body)))

		if self.reason is None:
			self.reason = HTTPResponseReasons[self.code] if self.code in HTTPResponseReasons else 'Pink kittens'

		t = '%s %s %s\r\n' % (self.version.value, self.code, self.reason)
		for key, value in self.headers.items():
			if isinstance(value, enum.Enum):
				t += '%s: %s\r\n' % (key, self.headers[key].name.lower())
			else:
				t += '%s: %s\r\n' % (key, self.headers[key])
		t += '\r\n'
		t = t.encode('ascii')
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


class HTTPServerMode(enum.Enum):
	PROXY = 'PROXY'
	CREDSTEALER = 'CREDSTEALER'


class HTTPBasicAuth:
	"""
	Handling HTTP basic Auth
	verify_creds: can be a  1. dictionary with user:password pairs.
						 2. empty dict means nobody is allowed
						 3. None means EVERYBODY IS ALLOWED
	"""

	def __init__(self, verify_creds = None):
		self._iterations = 0
		self.verify_creds = verify_creds

	async def do_AUTH(self, http_request, http_server):
		try:
			auth_header_key = 'Authorization' if http_server.session.server_mode != HTTPServerMode.PROXY else 'Proxy-Authorization'
			#print('hdr key: %s' % auth_header_key)
			req_auth_header = http_request.get_header(auth_header_key)
			#print('Auth header: %s' % req_auth_header)
			if req_auth_header is not None and req_auth_header[:5].upper() == 'BASIC':
				temp = base64.b64decode(req_auth_header[5:]).decode('ascii')
				marker = temp.find(':')
				if marker == -1:
					http_server.log('Invalid BASIC auth field!')
					return
				user_creds = BASICUserCredentials()
				user_creds.username = temp[:marker]
				user_creds.password = temp[marker+1:]

				await http_server.logger.credential(user_creds.to_credential())

				if user_creds.verify(self.verify_creds):
					http_server.session.current_state = HTTPState.AUTHENTICATED
				else:
					http_server.session.current_state = HTTPState.AUTHFAILED

			else:
				if http_server.session.server_mode == HTTPServerMode.PROXY:
					a = await asyncio.wait_for(http_server.send_data(HTTP407Resp('Basic').to_bytes()), timeout = 1)
				else:
					a = await asyncio.wait_for(http_server.send_data(HTTP401Resp('Basic').to_bytes()), timeout = 1)
				return
		except Exception as e:
			await http_server.loggerexception()


class BASICUserCredentials:
	def __init__(self):
		self.username = None
		self.password = None

	def to_credential(self):
		cred = Credential(
			'Cleartext',
			username = self.username,
			password = self.password,
			fullhash = '%s:%s' % (self.username, self.password)
		)
		return cred

	def verify(self, verify_creds):
		if verify_creds is None:
			return True
		else:
			if self.username in verify_creds:
				return verify_creds[self.username] == self.password
			else:
				return False


class HTTPNTLMAuth:
	def __init__(self, verify_creds = None, ntlm_settings = None):
		self.handler = NTLMAUTHHandler()
		self.handler.setup(ntlm_settings, verify_creds)
		self.verify_creds = verify_creds
		self.ntlm_settings = ntlm_settings

	async def do_AUTH(self, http_request, httpserver):
		try:
			auth_header_key = 'Authorization' if httpserver.session.server_mode != HTTPServerMode.PROXY else 'Proxy-Authorization'
			req_auth_header = http_request.get_header(auth_header_key)
			if req_auth_header is not None and req_auth_header[:4].upper() == 'NTLM':
				auth_status, ntlm_message, creds = self.handler.do_AUTH(base64.b64decode(req_auth_header[5:]))
				if creds is not None:
					for cred in creds:
						await httpserver.logger.credential(cred.to_credential())

				if auth_status == NTStatus.STATUS_MORE_PROCESSING_REQUIRED:
					if httpserver.session.server_mode == HTTPServerMode.PROXY:
						a = await asyncio.wait_for(httpserver.send_data(HTTP407Resp('NTLM '+ base64.b64encode(ntlm_message).decode('ascii')).to_bytes()), timeout =1 )
					else:
						a = await asyncio.wait_for(httpserver.send_data(HTTP401Resp('NTLM '+ base64.b64encode(ntlm_message).decode('ascii')).to_bytes()), timeout =1 )
					return

				elif auth_status == NTStatus.STATUS_ACCOUNT_DISABLED:
					httpserver.session.current_state = HTTPState.AUTHFAILED

				elif auth_status == NTStatus.STATUS_SUCCESS:
					httpserver.session.current_state = HTTPState.AUTHENTICATED

				else:
					raise Exception('Unexpected status')
			else:
				if httpserver.session.server_mode == HTTPServerMode.PROXY:
					a = await asyncio.wait_for(httpserver.send_data(HTTP407Resp('NTLM').to_bytes()), timeout = 1)
				else:
					a = await asyncio.wait_for(httpserver.send_data(HTTP401Resp('NTLM').to_bytes()), timeout = 1)
				return
		except Exception as e:
			await httpserver.logger.exception()
