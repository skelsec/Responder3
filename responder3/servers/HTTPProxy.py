import copy
import traceback
import struct
from base64 import b64decode
import logging
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP, ProtocolSession

from responder3.utils import *
from responder3.protocols.HTTP import *

class HTTPSession(ProtocolSession):
	def __init__(self, server):
		ProtocolSession.__init__(self, server)
		#for protocol-level
		self._headersRecieved = False
		self.cmdParser    = HTTPRequestParser(encoding = 'utf-8')
		#for
		self.HTTPVersion          = HTTPVersion.HTTP11
		self.HTTPContentEncoding  = HTTPContentEncoding.IDENTITY
		self.HTTPConectentCharset = 'utf8'
		self.HTTPAtuhentication   = None
		self.HTTPCookie           = None
		self.HTTPServerBanner     = None
		self.currentState         = HTTPState.UNAUTHENTICATED

	def __repr__(self):
		t  = '== HTTPSession ==\r\n'
		t += '_headersRecieved: %s\r\n' % repr(self._headersRecieved)
		t += 'cmdParser:        %s\r\n' % repr(self.cmdParser)
		t += 'HTTPVersion:      %s\r\n' % repr(self.HTTPVersion)
		t += 'HTTPContentEncoding: %s\r\n' % repr(self.HTTPContentEncoding)
		t += 'HTTPConectentCharset: %s\r\n' % repr(self.HTTPConectentCharset)
		t += 'HTTPAtuhentication: %s\r\n' % repr(self.HTTPAtuhentication)
		t += 'HTTPCookie:       %s\r\n' % repr(self.HTTPCookie)
		t += 'HTTPServerBanner: %s\r\n' % repr(self.HTTPServerBanner)
		t += 'currentState:     %s\r\n' % repr(self.currentState)
		return t

class HTTPProxy(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		

	def modulename(self):
		return 'HTTPProxy'

	def setup(self):
		self.protocol = HTTPProtocol
		self.protocolSession = HTTPSession(self.rdnsd)
		#put settings parsing here!
		if self.settings is None:
			#default settings, basically just NTLm auth
			self.protocolSession.HTTPAtuhentication   = HTTPNTLMAuth(isProxy = True)

		else:
			if 'authentication' in self.settings:
				#supported authentication mechanisms
				if self.settings['authentication']['authmecha'].upper() == 'NTLM':
					self.protocolSession.HTTPAtuhentication   = HTTPNTLMAuth(isProxy = True)
					if 'settings' in self.settings['authentication']:
						self.protocolSession.HTTPAtuhentication.setup(self.settings['authentication']['settings'])
				elif self.settings['authmecha'].upper() == 'BASIC':
					self.protocolSession.HTTPAtuhentication  = HTTPBasicAuth(isProxy = True)

				else:
					raise Exception('Unsupported HTTP authentication mechanism: %s' % (self.settings['authentication']['authmecha']))

				if 'cerdentials' in self.settings['authentication']:
					self.protocolSession.HTTPAtuhentication.verifyCreds = self.settings['authentication']['cerdentials']
			else:
				self.protocolSession.currentState = HTTPState.AUTHENTICATED


		return

	def handle(self, httpReq, transport, session):
		try:
			if 'R3DEEPDEBUG' in os.environ:
				print(repr(session))
				self.log(logging.INFO,'Session state: %s Request: %s' % ( (session.currentState.name if session.currentState is not None else 'NONE') , repr(httpReq)), session)

			if session.currentState == HTTPState.UNAUTHENTICATED and session.HTTPAtuhentication is None:
				session.currentState == HTTPState.AUTHENTICATED

			#if httpReq.method not in ['CONNECT']:
			
			if session.currentState == HTTPState.UNAUTHENTICATED:
				usercreds = session.HTTPAtuhentication.do_AUTH(httpReq, transport, session)
				if usercreds is not None:
					if isinstance(usercreds, list):
						for uc in usercreds:
							self.logResult(session, uc.toResult())
					else:
						self.logResult(session, usercreds.toResult())

			if session.currentState == HTTPState.AUTHFAILED:
				transport.write(HTTP403Resp(session, 'Basic').toBytes())
				transport.close()
				return

			if session.currentState == HTTPState.AUTHENTICATED:
				#at this stage httpReq could be etiher a GET or a CONNECT request. CONNECT request is for HTTPS connections
				if httpReq.method == 'GET':
					#parse url
					#connect to hostname
					#send modified request to dest server (uri needs to be converted from full url to actual uri)
					#read response
					#parse response
					#return response
					pass
				elif httpReq.method == 'CONNECT':
					pass
				else:
					#sending bad request
					transport.write(HTTP400Resp(session, body='This is a proxy...').toBytes())
					transport.close()
					return
				

		except Exception as e:
			traceback.print_exc()
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			pass

class HTTPProtocol(ResponderProtocolTCP):
	
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)
		#reasoning: HTTP server does the parsing of the settings, but some setting parameters are modifying the session object
		self._session = copy.deepcopy(server.protocolSession)

	def _parsebuff(self):
		if len(self._buffer) > self._buffer_maxsize:
			raise Exception('Data in buffer too large!')

		if not self._session._headersRecieved:
			marker = self._buffer.find(b'\r\n\r\n') 
			if marker == -1:
				return
			else:
				#buffer contains header data
				self._session._headersRecieved = True
				self._ramainingData = self._session.cmdParser.parseHeader(self._buffer[:marker])
				self._buffer = self._buffer[marker+4:]


		if self._session._headersRecieved and len(self._buffer) >= self._ramainingData:
			#we have recieved all data for the request, and the request contained body data
			httpreq = self._session.cmdParser.parseBody(self._buffer[:self._ramainingData])
			self._buffer = self._buffer[self._ramainingData:]
			self._session._headersRecieved = False

			self._server.handle(httpreq, self._transport, self._session)
			
			if len(self._buffer) > 0:
				#keep parsing until we consumed all data
				self._parsebuff()

		return
		

		
	def _parsereq(self):
		req = self._session.cmdParser.parse(io.BytesIO(self._buffer[:marker+1]))
		
		self._server.handle(_httpreq, self._transport)

class HTTPSProxy(HTTPProxy):
	def modulename(self):
		return 'HTTPSProxy'


