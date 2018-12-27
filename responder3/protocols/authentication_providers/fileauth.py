from responder3.protocols.authentication_providers.dictauth import DictAuth

class FileAuth(DictAuth):
	def __init__(self, ):
		DictAuth.__init__(self)
		self.credential_file = None
		self.parse_credfile()

	def setup_defaults(self):
		raise Exception('There are no default settings for fileauth!')

	def setup(self, d):
		self.credential_file = d['credfile']
		self.parse_credfile()

	def test_domain(self, domain):
		return domain in self.credentials

	def parse_credfile(self):
		with open(self.credential_file, 'r') as f:
			for line in f:
				line = line.strip()
				domain, username, password = line.strip(':')
				if domain not in self.credentials:
					self.credentials[domain] = {}
				if username not in self.credentials[domain]:
					self.credentials[domain][username] = password
				else:
					print('Multiple password for %s:%s, owerwriting password!' % (domain, username))