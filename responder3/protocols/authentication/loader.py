from responder3.protocols.authentication.common import *
from responder3.protocols.authentication.CRAM import *
from responder3.protocols.authentication.DIGEST import *
from responder3.protocols.authentication.BASIC import BASIC
from responder3.protocols.authentication.SASL import *
from responder3.protocols.authentication.NTLM import NTLMAUTHHandler

from responder3.protocols.authentication_providers.dictauth import DictAuth
from responder3.protocols.authentication_providers.fileauth import FileAuth
from responder3.protocols.authentication_providers.common import *

class AuthMechaLoader:
	def __init__(self):
		pass

	@staticmethod
	def from_dict(d):
		mecha = AuthMecha(d['auth_mecha'].upper())
		credential_provider = DictAuth()
		credential_provider.setup_defaults()
		if 'credentials_provider' in d:
			credential_provider = credprov2class[d['credentials_provider']['name'].upper()]()
			if 'settings' in d['credentials_provider']:
				credential_provider.setup(d['credentials_provider']['settings'])
			else:
				credential_provider.setup_defaults()
		
		auth_obj = authmecha2class[mecha]( credential_provider)
		if 'settings' in d:
			auth_obj.setup(d['settings'])
		else:
			auth_obj.setup_defaults()
		return mecha, auth_obj

	@staticmethod
	def from_json(self, data):
		return AuthMechaLoader.from_dict(json.loads(data))


authmecha2class = {
	AuthMecha.BASIC : BASIC,
	AuthMecha.CRAM : None,
	AuthMecha.DIGEST : DIGEST,
	AuthMecha.SASL : None,
	AuthMecha.NTLM : NTLMAUTHHandler,
}

credprov2class = {
	CredProvider.DICT : DictAuth,
	CredProvider.FILE : FileAuth,
}