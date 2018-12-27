# https://tools.ietf.org/html/rfc7617
import enum
import collections
import base64

from responder3.protocols.authentication.common import *
from responder3.protocols.authentication_providers.credential_objects import *

class BASICStatus:
	START = enum.auto()
	AUTHENTICATE = enum.auto()
	AUTHORIZE = enum.auto()
	FINISH = enum.auto()

class BASICAuthenticate:
	def __init__(self):
		self.realm  = None
		self.auth_params = []

	def to_line(self):
		data = ''
		if self.realm:
			data += 'realm=%s' % self.realm
		return data

	@staticmethod
	def from_dict(kv):
		ds = BASICAuthenticate()
		ds.realm = kv.get('realm')
		if 'auth' in kv:
			ds.auth_param = kv['auth'].split(',')
		return ds

	@staticmethod
	def from_line(self, data):
		kv = {}
		if data.find(',') != -1:
			for elem in data.split(','):
				key, value = elem.split('=')
				if value[0] == '"':
					value = value[1:-1]
				kv[key] = value
			da = BASICAuthenticate.from_dict(kv)
		return da

class BASICAuthorize:
	def __init__(self):
		self.username = None
		self.password = None

	def to_line(self):
		temp = '%s:%s' % (self.username, self.password)
		data = 'Basic %s' % base64.b64encode(temp)
		return data

	@staticmethod
	def from_dict(kv):
		ds = BASICAuthorize()
		ds.username = kv['username']
		ds.password = kv['password']
		return ds

	@staticmethod
	def from_line(data):
		temp = base64.b64decode(data.strip()).decode()
		kv = {}
		kv['username'] = temp.split(':')[0]
		kv['password'] = temp.split(':')[1]
		da = BASICAuthorize.from_dict(kv)
		return da

class BASIC:
	def __init__(self, credentials):
		self.mode = None #AUTHModuleMode SERVER or CLIENT
		self.status = BASICStatus.START
		self.credentials = credentials
		self.authenticate = None
		self.authorize = None

	def setup_defaults(self):
		self.authenticate = BASICAuthenticate()
		self.mode = AUTHModuleMode.SERVER
		return

	def setup(self, config):
		self.mode = AUTHModuleMode(config['mode'].upper())
		if self.mode == AUTHModuleMode.SERVER:
			self.authenticate = BASICAuthenticate.from_dict(config['authenticate'])
		else:
			self.authorize = BASICAuthorize.from_dict(config['authorize'])

	def verify_creds(self):
		"""
		Verifyies user creds, returns a tuple with (verification_result, credential)
		"""
		credential = PlaintextCredential(None, self.authorize.username, self.authorize.password)
		password = self.credentials.get_password('',self.authorize.username)
		if password == self.authorize.password:
			return AuthResult.OK, credential
		else:
			return AuthResult.FAIL, credential

	def do_auth(self, data = None):
		if self.mode == AUTHModuleMode.SERVER:
			if self.status == BASICStatus.START:
				if data is None:
					self.status = BASICStatus.AUTHORIZE
					#returning WWW-Authenticate data
					return AuthResult.CONTINUE, self.authenticate.to_line()
					
				else:
					self.status = BASICStatus.AUTHORIZE

			if self.status == BASICStatus.AUTHORIZE:
				if data is not None:
					#evaulation client's credentials
					self.status = BASICStatus.FINISH
					self.authorize = BASICAuthorize.from_line(data)
					return self.verify_creds()
				else:
					raise Exception('BASIC AUTH: input data expected in SERVER|AUTHORIZE state')

			else:
				raise Exception('BASIC AUTH: Unexpected SERVER state')

		elif self.mode == AUTHModuleMode.CLIENT:
			if self.status == BASICStatus.START:
				if data is not None:
					#returning WWW-Authorize data
					self.status = BASICStatus.FINISH
					self.authenticate = BASICAuthenticate.to_line()
					self.authorize = BASICAuthorize.construct(self.authenticate, credential)
					return AuthResult.OK, self.authorize.to_line()
				else:
					raise Exception('BASIC AUTH: input data expected in SERVER|AUTHORIZE state')

		else:
			raise Exception('BASIC Unknown mode')