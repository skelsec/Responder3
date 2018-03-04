import logging
import asyncio

from responder3.core.commons import *
from responder3.protocols.HTTP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

class HTTPSession(ResponderServerSession):
	def __init__(self, *args):
		ResponderServerSession.__init__(self, *args)
		self.HTTPVersion          = HTTPVersion.HTTP11
		self.HTTPContentEncoding  = HTTPContentEncoding.IDENTITY
		self.HTTPConectentCharset = 'utf8'
		self.HTTPAtuhentication   = None
		self.HTTPCookie           = None
		self.HTTPServerBanner     = None
		self.currentState         = HTTPState.UNAUTHENTICATED

	def __repr__(self):
		t  = '== HTTPSession ==\r\n'
		t += 'HTTPVersion:      %s\r\n' % repr(self.HTTPVersion)
		t += 'HTTPContentEncoding: %s\r\n' % repr(self.HTTPContentEncoding)
		t += 'HTTPConectentCharset: %s\r\n' % repr(self.HTTPConectentCharset)
		t += 'HTTPAtuhentication: %s\r\n' % repr(self.HTTPAtuhentication)
		t += 'HTTPCookie:       %s\r\n' % repr(self.HTTPCookie)
		t += 'HTTPServerBanner: %s\r\n' % repr(self.HTTPServerBanner)
		t += 'currentState:     %s\r\n' % repr(self.currentState)
		return t

class HTTP(ResponderServer):
	def init(self):
		self.parser = HTTPRequest
		self.parse_settings()
		

	def parse_settings(self):
		if self.settings is None:
			#default settings, basically just NTLM auth
			self.session.HTTPAtuhentication   = HTTPNTLMAuth()
			self.session.HTTPAtuhentication.setup()
			
		else:
			if 'authentication' in self.settings:
				#supported authentication mechanisms
				if self.settings['authentication']['authmecha'].upper() == 'NTLM':
					self.session.HTTPAtuhentication   = HTTPNTLMAuth()
					if 'settings' in self.settings['authentication']:
						self.session.HTTPAtuhentication.setup(self.settings['authentication']['settings'])
				
				elif self.settings['authmecha'].upper() == 'BASIC':
					self.session.HTTPAtuhentication  = HTTPBasicAuth()

				else:
					raise Exception('Unsupported HTTP authentication mechanism: %s' % (self.settings['authentication']['authmecha']))

				if 'cerdentials' in self.settings['authentication']:
					self.session.HTTPAtuhentication.verifyCreds = self.settings['authentication']['cerdentials']


	@asyncio.coroutine
	def parse_message(self):
		req = yield from asyncio.wait_for(self.parser.from_streamreader(self.creader), timeout = 10)
		return req

	@asyncio.coroutine
	def send_data(self, data):
		self.cwriter.write(data)
		yield from self.cwriter.drain()

	@asyncio.coroutine
	def run(self):
		try:
			while True:
				req = yield from asyncio.wait_for(self.parse_message(), timeout = 10)
				#print(req)
				
				if self.session.currentState == HTTPState.UNAUTHENTICATED and self.session.HTTPAtuhentication is None:
					self.session.currentState == HTTPState.AUTHENTICATED
				
				if self.session.currentState == HTTPState.UNAUTHENTICATED:
					yield from self.session.HTTPAtuhentication.do_AUTH(req, self)

				if self.session.currentState == HTTPState.AUTHFAILED:
					yield from asyncio.wait_for(self.send_data(HTTP403Resp('Auth failed!').toBytes()), timeout = 1)
					self.cwriter.close()
					return

				if self.session.currentState == HTTPState.AUTHENTICATED:
					#serve webpage or whatever
					yield from asyncio.wait_for(self.send_data(HTTP200Resp(body = 'SUCCSESS!').toBytes()), timeout = 1)
					self.cwriter.close()
					return

		except Exception as e:
			self.logexception()
			pass