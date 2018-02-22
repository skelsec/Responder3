import hashlib
import hmac

from responder3.crypto.BASE import hashBASE

class md4(hashBASE):
	def __init__(self, data = None):
		hashBASE.__init__(self, data)
	def setup_hash(self):
		self._hash = hashlib.new('md4')
	def update(self, data):
		return self._hash.update(data)
	def digest(self):
		return self._hash.digest()
	def hexdigest(self):
		return self._hash.hexdigest()

class hmac_md5():
	def __init__(self, key):
		hashBASE.__init__(self, key)
	def setup_hash(self):
		self._hmac = hmac.new(self._key, digestmod = hashlib.md5)
	def update(self, data):
		return self._hmac.update(data)
	def digest(self):
		return self._hmac.digest()
	def hexdigest(self):
		return self._hmac.hexdigest()	

class sha256():
	def __init__(self, data = None):
		hashBASE.__init__(self, data)
	def setup_hash(self):
		self._hash = hashlib.new('sha256')
	def update(self, data):
		return self._hash.update(data)
	def digest(self):
		return self._hash.digest()
	def hexdigest(self):
		return self._hash.hexdigest()	