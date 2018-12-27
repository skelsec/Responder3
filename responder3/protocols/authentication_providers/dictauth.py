

class DictAuth:
	def __init__(self):
		self.credentials = None

	def setup(self, d):
		self.credentials = d['creds']

	def setup_defaults(self):
		self.credentials = {}

	def test_domain(self, domain):
		return domain in self.credentials

	def test_username(self, domain, username):
		res = self.test_domain(domain)
		if res == True:
			return username in self.credentials[domain]
		return False

	def test_password(self, plaintext_cred):
		password = self.get_password(plaintext_cred.domain, plaintext_cred.username)
		if password == False:
			return False
		if password == plaintext_cred.password:
			return True
		return False

	def get_password(self, domain, username):
		res = self.test_username(domain, username)
		if res == True:
			return self.credentials[domain][username]
		return False

	def yield_credentials(self):
		for domain in self.credentials:
			for username in self.credentials[domain]:
				yield PlaintextCredential(domain, username, password)
