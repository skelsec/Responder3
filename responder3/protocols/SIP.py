# https://www.rfc-editor.org/rfc/rfc3261.txt

import io
import enum
import asyncio
import traceback

from responder3.core.logging.log_objects import Credential
from responder3.core.commons import read_element
from responder3.core.asyncio_helpers import *

class VIAHeader:
	def __init__(self):
		self.transport = None
		self.sent_by_addr = None
		self.received = None
		self.rport = None
		self.branch = None

class AUTHORIZATIONHeader:
	def __init__(self):
		#Digest username="asdfashfgha", realm="sip.cybercity.dk", nonce="1701af566be182070084c6f740706bb", 
		#uri="sip:192.168.42.211:5066", response="713996be6fe3557c4400f28fb10977b8", algorithm=MD5, opaque="1701a1351f70795"
		self.auth_type = None
		self.username = None
		self.realm = None
		self.nonce = None
		self.uri = None
		self.response = None
		self.algorithm = None
		self.opaque = None

		self.unknown_tags = {}

	@staticmethod
	def from_bytes(bbuff):
		ah = AUTHORIZATIONHeader()
		m = bbuff.find(' ')
		if m == -1:
			raise Exception('Wrong Authroization header format!')
		ah.auth_type = bbuff[:m].strip()
		tags = bbuff[m+1:].split(',')
		for raw_tag in tags:
			tag = rawtag.strip()
			m = tag.find('=')
			if m == -1:
				raise Exception('Wrong Authroization header format!')
			tag_key = tag[:m]
			tag_value = tag[m+1:].strip()
			if tag_value[0] == '"':
				tag_value = tag_value[1:-1]

			if tag_key.lower() == 'username':
				self.username = tag_value
			elif tag_key.lower() == 'realm':
				self.realm = tag_value
			elif tag_key.lower() == 'nonce':
				self.nonce = tag_value
			elif tag_key.lower() == 'uri':
				self.uri = tag_value
			elif tag_key.lower() == 'response':
				self.response = tag_value
			elif tag_key.lower() == 'algorithm':
				self.algorithm = tag_value
			elif tag_key.lower() == 'opaque':
				self.opaque = tag_value
			else:
				self.unknown_tags[tag_key] = tag_value


	def get_sip_hash(self, method = 'REGISTER'):
		#$sip$*192.168.100.100*192.168.100.121*username*asterisk*REGISTER*sip*192.168.100.121**2b01df0b****MD5*ad0520061ca07c120d7e8ce696a6df2d 
		return '$sip$*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s' % (self.uri, '', self.username, self.realm, method, self.uri_prefix, '', '', self.nonce, '','', self.algorithm, self.response)

		#$sip$*[URI_SERVER]*[URI_CLIENT]*[USERNAME]*[REALM]*[METHOD]*[URI_PREFIX]*[URI_RESOURCE]*[URI_SUFFIX]*[NONCE_SERVER]*[NONCE_CLIENT]*[NONCE_COUNT]*[QOP]*[DIRECTIVE]*[MD5]
		#$sip$*sipConfusedip.aaa.it**33333*sip.aaa.it*REGISTER*sip*sip.aaa.it**1234****MD5*7468b74b7257b05671242ad0a8b0eb16'


class Request:
	def __init__(self):
		self.method = None
		self.request_uri = None
		self.sip_version = None

		self.headers = {}
		self.data = None

		#special headers for making this module lighter (otherwise we'd implement the headers as objects)
		self.spec_headers = {}

	@staticmethod
	async def from_streamreader(reader, timeout = 10):
		req = Request()
		line = await readline_or_exc(reader, timeout)
		req.method, req.request_uri, req.sip_version = line.decode().strip().split(' ')

		hdr_blob = await readuntil_or_exc(reader, b'\r\n\r\n', timeout)
		hdr_blob = hdr_blob.decode()
		hdr_lines = hdr_blob.split('\r\n')
		
		prev_key = None
		for line in hdr_lines:
			if line == '':
				continue
			m = line.find(':')
			if m == -1:
				self.headers[prev_key] += line.strip()
			else:
				key = line[:m].strip()
				prev_key = key
				req.headers[key] = line[m+1:].strip()
				req.spec_headers[key.lower()] = line[m+1:].strip()

		if 'content-length' in req.spec_headers:
			req.data = await readexactly_or_exc(reader, int(req.spec_headers['content-length']), timeout)

		return req

	def __str__(self):
		t = '============ SIP Request ================\r\n'
		t += ' '.join([self.method, self.request_uri, self.sip_version])
		t += '\r\n'
		for key in self.headers:
			t += '%s: %s\r\n' % (key, self.headers[key])
		if self.data:
			t += self.data.hex()
		return t


class Response:
	def __init__(self):
		self.sip_version = None
		self.status_code = None
		self.reason = None

		self.headers = {}
		self.data = None

	def to_bytes(self):
		status_line = ' '.join([self.sip_version, self.status_code, self.reason])
		t = status_line + '\r\n'
		for key in self.headers:
			t += '%s: %s\r\n' % (key, self.headers[key])
		t+= '\r\n'
		t = t.encode()
		if self.data:
			t += data
		return t

	@staticmethod
	async def from_streamreader(reader, timeout = 10):
		resp = Response()
		line = await readline_or_exc(reader, timeout)
		resp.sip_version, resp.status_code, resp.reason = line.decode().strip().split(' ')

class SIP401Response(Response):
	def __init__(self):
		Response.__init__(self)
		self.sip_version = 'SIP/2.0'
		self.status_code = '401'
		self.reason = 'Unauthorized'

	@staticmethod
	def from_request(req, auth_data):
		resp = SIP401Response()
		for key in ['Call-ID', 'CSeq', 'From', 'To', 'Via']:
			resp.headers[key] = req.headers[key]
		resp.headers['WWW-Authenticate'] = auth_data
		resp.headers['Content-Length'] = 0
		return resp
