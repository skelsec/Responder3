from responder3.core.logging.log_objects import Credential

class PlaintextCredential:
	def __init__(self, domain, username, password):
		self.domain = domain
		self.username = username
		self.password = password

	def to_credential(self):
		if self.domain:
			return Credential(
				'plaintext',
				domain = self.domain,
				username = self.username,
				password = self.password,
				fullhash = '%s:%s:%s' % (self.domain, self.username, self.password)
			)
		else:
			return Credential(
				'plaintext',
				username = self.username,
				password = self.password,
				fullhash = '%s:%s' % (self.username, self.password)
			)