import enum
from base64 import b64encode, b64decode

class PLAIN():
	"""
	Handling SMTP plaintext Auth
	credsDict: can be a  1. dictionary with user:password pairs.
						 2. empty dict means nobody is allowed
						 3. None means EVERYBODY IS ALLOWED
	"""

	def __init__(self, credsDict = {}):
		self._credentials = credsDict
		self._passes      = 0
		self._username    = None
		self._password    = None
	
	def getAuthData(self):
		if self._passes == 0:
			self._passes += 1
			return 'VXNlcm5hbWU6' #Username
		
		elif self._passes == 1:
			self._passes += 1
			return 'UGFzc3dvcmQ6' #Password
		
		else:
			raise Exception('Too many calls to getAuthData')

	def setAuthData(self, data):
		if self._passes == 0:
			authData = b64decode(data).split(b'\x00')[1:]
			self._username    = authData[0].decode('ascii')
			self._password    = authData[1].decode('ascii')

		elif self._passes == 1:
			self._username = b64decode(data).replace(b'\x00').decode('ascii')
		
		elif self._passes == 2:
			self._password = b64decode(data).replace(b'\x00').decode('ascii')

		else:
			raise Exception('Too many calls to setAuthData')

	def isMoreData(self):
		if self._passes != 2:
			return True
		return False

	def checkCredentials(self, response = None):
		if self._username is not None and self._password is not None:
			if self._credentials is None:
				return True

			if self._username in self._credentials:
				if self._password == self._credentials[self._username]:
					return True

		return False


class CRAMMD5():
	def __init__(self):
		self._credentials = None
		self.random = ''
		self.timestamp = ''
		self.FQND = ''

	def getAuthData(self):
		return b64encode('<%s.%s@%s>')

	def checkAuth(self, response):
		pass