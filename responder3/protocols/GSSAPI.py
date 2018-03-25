import pprint
from asn1crypto.core import ObjectIdentifier,Choice, Any, SequenceOf, BitString, Sequence, GeneralString, OctetString, Enumerated
from responder3.protocols.NTLM import *

##Meterial used:
##https://msdn.microsoft.com/en-us/library/cc247039.aspx
##http://www.rfc-editor.org/rfc/rfc4178.txt

##ASN1 parsing libray: asn1crypto
##docu: https://github.com/wbond/asn1crypto/blob/master/docs/universal_types.md
#memo
#only use explicit key with (class, tag) tuple!

##class options: 
"""
CLASS_NUM_TO_NAME_MAP = {
    0: 'universal',
    1: 'application',
    2: 'context',
    3: 'private',
}
"""
##



class MechType(ObjectIdentifier):
	_map = { 
		#'': 'SNMPv2-SMI::enterprises.311.2.2.30',
		'1.3.6.1.4.1.311.2.2.10': 'NTLMSSP - Microsoft NTLM Security Support Provider',
		'1.2.840.48018.1.2.2'   : 'MS KRB5 - Microsoft Kerberos 5',
		'1.2.840.113554.1.2.2'  : 'KRB5 - Kerberos 5',
		'1.2.840.113554.1.2.2.3': 'KRB5 - Kerberos 5 - User to User',
		'1.3.6.1.4.1.311.2.2.30': 'NEGOEX - SPNEGO Extended Negotiation Security Mechanism',
	}

class MechTypes(SequenceOf):
	_child_spec = MechType

class ContextFlags(BitString):
	_map = {
		0: 'delegFlag',
		1: 'mutualFlag',
		2: 'replayFlag',
		3: 'sequenceFlag',
		4: 'anonFlag',
		5: 'confFlag',
		6: 'integFlag',
	}

class NegHints(Sequence):
	_fields = [
		('hintName', GeneralString, {'explicit': 0, 'optional': True}),
		('hintAddress', OctetString, {'explicit': 1, 'optional': True}),
]
 

class NegTokenInit2(Sequence):
	class_ = 2
	tag = 0
	
	_fields = [
		('mechTypes', MechTypes, {'explicit': 0,'optional': True}),
		('reqFlags', ContextFlags, {'explicit': 1 ,'optional': True}),
		('mechToken', OctetString, {'explicit': 2 ,'optional': True,}),
		('negHints', NegHints, {'explicit': 3 ,'optional': True}),
		('mechListMIC', OctetString, {'explicit': 4 ,'optional': True}),
]


class negState(Enumerated):
	_map = {
		0: 'accept-completed',
		1: 'accept-incomplete',
		2: 'reject',
		3: 'request-mic',
	}

class negTokenResp(Sequence):
	_fields = [
		('negState', negState, {'explicit': 0,'optional': True}),
		('supportedMech', MechType, {'explicit': 1, 'optional': True}),
		('responseToken', OctetString, {'explicit': 2, 'optional': True}),
		('mechListMIC', OctetString, {'explicit': 3,'optional': True}),
]

class NegotiationToken(Choice):
	_alternatives = [
		#('NegTokenInit2', NegTokenInit2, {'implicit': (0,16) }  ), #NegTokenInit2 the '2' in the name is because Microsoft added modifications to the original rfc :)
		('NegTokenInit2', NegTokenInit2, {'implicit': (0,16) }  ), #NegTokenInit2 the '2' in the name is because Microsoft added modifications to the original rfc :)
		('negTokenResp', negTokenResp, {'explicit': (2,1) } ),
		
	]

class SPNEGO(Sequence):
	class_ = 2
	tag    = 0

	_fields = [
		('NegotiationToken', NegotiationToken),
]

class GSSType(ObjectIdentifier):
	_map = { 
		#'': 'SNMPv2-SMI::enterprises.311.2.2.30',
		'1.3.6.1.5.5.2': 'SPNEGO',
	}

class GSSAPI(Sequence):
	class_ = 1
	tag    = 0

	_fields = [
		('type', GSSType, {'optional': False}),
		('value', Any, {'optional': False}),
	]

	_oid_pair = ('type', 'value')
	_oid_specs = {
		'SPNEGO': SPNEGO,
	}

class GSSAPIAuthHandler():
	def __init__(self):
		self.supported_authtypes = None
		self.common_authtypes = None
		self.chosen_authtype = None
		self.authHandler = None
		self.negTokenInit = None
		self.negTokenResp_server = None
		self.negTokenResp = None
		self.app = None

	def do_AUTH(self, asn1_blob = None, smbv1 = False):

		if asn1_blob is None:
			self.negTokenInit = {}
			self.negTokenInit['mechTypes'] = [MechType('1.3.6.1.4.1.311.2.2.10')]
			
			if not smbv1:
				self.negTokenInit['negHints']  = NegHints({'hintName': 'testserver@testdomain.local', 'hintAddress':b'bela'})
			else:
				self.negTokenInit['negHints']  = NegHints({'hintName': 'testserver@testdomain.local'})

			self.aaa = NegotiationToken({'NegTokenInit2':self.negTokenInit})

			spnego = SPNEGO({'NegotiationToken':self.aaa})

			self.app = GSSAPI({'type': GSSType('1.3.6.1.5.5.2'), 'value':spnego})
			
			#self.app.debug()
			#pprint.pprint(self.app)
			return (None, self.app.dump(), None)
		
		else:
			if self.negTokenResp_server is None:
				self.app = GSSAPI.load(asn1_blob)
				#print(self.app.native['value']['NegotiationToken']['mechTypes'][0])
				#print(self.app.native['value']['NegotiationToken']['mechTypes'])

				if self.app.native['value']['NegotiationToken']['mechTypes'][0] == 'NTLMSSP - Microsoft NTLM Security Support Provider':
					self.authHandler = NTLMAUTHHandler()
					self.authHandler.setup()
				else:
					raise Exception('Unknown GSSAPI authentication type')

				status, responseData, creds = self.authHandler.do_AUTH(self.app.native['value']['NegotiationToken']['mechToken'])

				self.negTokenResp_server = {}
				self.negTokenResp_server['negState'] = negState(1)
				self.negTokenResp_server['responseToken']  = responseData

				t = NegotiationToken({'negTokenResp':negTokenResp(self.negTokenResp_server)})

				#spnego = SPNEGO({'NegotiationToken': t})

				return (status, t.dump(), creds)

			else:
				self.negTokenResp = NegotiationToken.load(asn1_blob)

				status, responseData, creds = self.authHandler.do_AUTH(self.negTokenResp.native['responseToken'])

				t = NegotiationToken({'negTokenResp': negTokenResp({'negState':  negState(0)})})

				return (status, t.dump(), creds)