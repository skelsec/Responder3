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
			
			self.app.debug()
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







#ExtensionId._map['1.3.6.1.5.5.2'] = 'SPNEGO - Simple Protected Negotiation'
##Extension._oid_specs['SPNEGO - Simple Protected Negotiation'] = GSSAPI
#
#if __name__ == '__main__':
#
"""
data = bytes.fromhex('605e06062b0601050502a0543052a024302206092a864882f71201020206092a864886f712010202060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265')
#print(data)
parsed = GSSAPI.load(data)
parsed.debug()


data2 = bytes.fromhex('3052a024302206092a864882f71201020206092a864886f712010202060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265')
parsed2 = NegTokenInit2.load(data2)
parsed2.debug()




####### NTLM GSSAPI over SMB authentication example
#client to server
ntlm_nego_req_gssapi = bytes.fromhex('604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000078208a2000000000000000000000000000000000501280a0000000f')
parsed = GSSAPI.load(ntlm_nego_req_gssapi, strict = True)
parsed.debug()
pprint.pprint(parsed.native)

#server to client
ntlm_chall_resp_gssapi = bytes.fromhex('a181a63081a3a0030a0101a10c060a2b06010401823702020aa2818d04818a4e544c4d53535000020000000a000a003800000005828aa2257147965534292500000000000000004800480042000000060072170000000f4900410053003000310002000a004900410053003000310001000a004900410053003000310004000a004900410053003000310003000a004900410053003000310007000800607eb34ac5c0cd0100000000')
parsed = NegotiationToken.load(ntlm_chall_resp_gssapi, strict = True)
parsed.debug()
pprint.pprint(parsed.native)

#client to server
ntlm_auth_gssapi = bytes.fromhex('a181bf3081bca281b90481b64e544c4d53535000030000001800180086000000180018009e00000012001200480000001a001a005a000000120012007400000000000000b6000000058288a20501280a0000000f500041004e0045004c005000430030003200410064006d0069006e006900730074007200610074006f007200500041004e0045004c0050004300300032008a7c1617ec88d45400000000000000000000000000000000a836c8ffec8ef97c96c997908dec9ad665c93b3a7c188cf6')
parsed = NegotiationToken.load(ntlm_auth_gssapi, strict = True)
parsed.debug()
pprint.pprint(parsed.native)

#server to client
ntlm_auth_gssapi = bytes.fromhex('a1073005a0030a0100')
parsed = NegotiationToken.load(ntlm_auth_gssapi, strict = True)
parsed.debug()
pprint.pprint(parsed.native)



####### Kerberos5 GSSAPI over SMB authentication example
print('=== Kerberos5 GSSAPI over SMB authentication example ===')
#client to server
print('Negotiate protocol response SMB, server sent supported mech types')
kerb5_auth_gssapi = bytes.fromhex('605e06062b0601050502a0543052a024302206092a864882f71201020206092a864886f712010202060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265')
parsed = GSSAPI.load(kerb5_auth_gssapi, strict = True)
parsed.debug()
pprint.pprint(parsed.native)
assert str(parsed['type']) == '1.3.6.1.5.5.2'
assert len(parsed.native['value']['NegotiationToken']['mechTypes']) == 4
assert len(parsed.native['value']['NegotiationToken']['mechToken']) == 2879

pprint.pprint(parsed.native['value'])


pprint.pprint(parsed.native['value']['NegotiationToken']['mechTypes'])

#server to client
print('Session setup request SMB, client sent supported mech types AND kerberos AP_REP')
kerb5_auth_gssapi_2 = bytes.fromhex('60820b8906062b0601050502a0820b7d30820b79a030302e06092a864882f71201020206092a864886f712010202060a2b06010401823702021e060a2b06010401823702020aa2820b4304820b3f60820b3b06092a864886f71201020201006e820b2a30820b26a003020105a10302010ea20703050020000000a3820466618204623082045ea003020105a1171b1553342e484f57544f2e41424152544c45542e4e4554a22d302ba003020102a12430221b04636966731b1a6f6265642e73342e686f77746f2e61626172746c65742e6e6574a382040d30820409a003020112a103020101a28203fb048203f7a7f64fc70af16f4a2193ddf8f03101e8df3e06864765f73213c73947b9a481893682bcb8f340d4adbd17da485aca7cf49cde6d2fbee2bc6bf9bc5e10ea9f20a3668594cc66e379df40190218d257bd967f3f83f73ee788ecc738c7cfb1e48c79015cecd72d38a86b71fd463902e10494123e4939f9bc1f087665db89dab4da8624267a8e8ddcaad73d4702feced7cbebee04dd1bf3a82e8de3ce6855909a4911e28a2baf9ed37aed69d01813bca5bbd2d85774549c6cfa966be110ae67ceddf70acd8ed1d0692e3169ed667fc5bd9aa46e35e571a4af24fd893b2c84f718d31d106279026fbec9e1cdcecbb32dbf66c6cfd18fe5d21939b26692654f387d7800666cbc3662ecafc8552f065713683598ad83d768445e733a0f8ffb32ccd1c52af8706e45782da0d3d2f36c286bebece9142da111152244b3067bfb5fd16bd30b23ab7524d33dcdb8d2a1a10d4cd84f2d44f6b6b34fae47617114b186996d4445c4e394c871f4a0fde902d1dfc5c16cfa0640440c36274b96b1d09e5e260af54d4a70dc775c7d779dbd6c487efdf3d4094c64a9ec5150b31c7b15bd06c8f6a69e82164146975b018641be467d4df62d11004df883c6f8c15460742ec4dccdbf41ababe48c5210aa1fa10dbb2f1cc8caacda4a7c30bf3dd87f7a9667f729f20a4f2f749d2b41181b1f4e0c5680a94cd04bd5a68c7e3070ea4ba848a1629370ca03201e95fdf9204835bb889c0d3f5f28d69c1089ab780e5a6cac585715c83159252463f4d73dde11ae8f536e9174c18071943117601803c8433450f127217cd253eddac4fc10474d51deb5ded1126b1138396f34160a4432321354ea8547511e4b11dfb973a4969a241c195327d4058c2ecc2a933f50c56b7c89addff19c5915d340d17a98e4db6fed74e6572c4d3f5cf9ddcd8d062c5361b751b03cf98fc2bb44da80adbec76686d2223111c36e1b4cfe3c3a5cb4e269da85eb685a48f6f3dfa91f99d7f50e840197a28eaba486c4bce9dd9c26d52ff6632d81a6a79c7b0d5f3cbfe7fa1865139e7f99451a7d01ef2f2d2912728e986bd90c53d63a97b096a04adc36f3e8375266fb8770f9a6bb98d954951fc93dbb8381fcc552363ad29fb981c349fe63e6191b4672966059429a01f00de0a8f7de223ca07e56639fa22de244dea34df70a0ae1a28cda55a41f59618b8f33c344986addb648491f2cc519c6a29c449697504d1e6a0f3e5096910f9c8c41c12666b7aaf78e82bad152cdbddd7af3d790a3689b7c8a1f491f663a0ee673742ebf74ffc8751097e28e8bcc43b8bdfa2b7c1be09df5f5abe0eda5bda67453628552fbb038f46b06b8ab081297e8b97696bccd6945d564f25ef8b08812b925ffb53f78f8f6aaf6748e33c0269141faecaac8eb6f8cc79b883e1002bb4005b5412dc42190240ba48206a5308206a1a003020112a28206980482069488de3f46dde369b99ae6156e8d82fb94dfe7d5ea49754d56cdc5cb558eebf5255047d1aa1866c395f64159b2ef47c503dfb5a2e34c067cbf92a9b47489fa0295410db41cd7b0ecb6f6d5f61fd1859300e8adee9feb07c038f718acbf51f2579856d0e6a6b830d571445dfa54d2770238776079f59cebdc5b0c4f1424b08be9cc2e6eb95065ed20a2d03c4ae504676cd0a1897363fe6bd30bd259644223d91e504c38d9739ffeb81276601146f0bf5c69e90aef985ded6743dc1deadc469eceeb5b81fc72be98a1de3369102635286ad94cb39c22624fd1e0803a2799cbd69c5ec54ae183c3947e837104d4081155216b8060a02223fd9f7ad16ca5022cddb67c4f2ea04f45972f0dfb5d21a00e4515412cbd4fb3ef88a76ae96c8b05efd5a98d101bf86eaa16c2cf6b25029563001fa2391a7ca2bb4ca1b790e12bbb81e51d1d5af51e2bbf4352c2e51ec7613994fd34646062af081d95b53cd5d19edd3f515849206a317bc549b748d7ae0608a6c9838a7460b4007eacbd28d571dc1f0a1ccd20cd2f0a1d197dc2dccf20006ae87037f5486a5dca55e3e2d89880200a07f743f9ca6090570c0ccb8e99d0f02a3904d351ac0fc12c8bd717113ccd51ed85958b5176173265b7e356a34a31c98bff61841b280d4e6c9e2becaf4c6a8fe0f60a5f18a466d6742b88179ae40552a8ee032ad24e0058897065d5cd3ea486d35e6b188bc47942356294d5eef6aaef6b7cc3c748b0e44220186cf108fb8c10420e8358aede075c857e4b1b029344c2a48b6a3b39586264e823e3321e602a9a1b024ffdbd011da59e977103e7ac090c4fa578d8105ae8eba7db4a5daece217746638e80d568de9b68d393312b80a6bf35db441698472ac1fe7b8808ee657d73b888def40ed770e728b7d64d1e2a941a756078575869f3abcbb457d1a3bb8a518e6a371dfea217effdaa571ef403c548280799e108501dbc4350607e1320c5cb3f1a97422a38b1ca808d64df0f890b6ea89e4d85cc4bafbe19e64c67e64728a9ba2db36e0bf3aa4c4456605e57c0d72c8e63af4e9e3679948611873ec471f2cf96fd96acede074463d5d5623637fb2d12e5e68928e06dd9bea91dcfacd2b9a774d5c0178509649fde7c6aa89deb7aad39ce670ec49391be4a826e144f704c3bef5ade0f1f6f79a984ccd5baaff6fa7bd4f82c25ae65dbced94050dc4b8c0f249255ff5804bb6ed656bb819e910f66f65f356a30dbee51a01558b9f99ccd03e6eb470bc8368c0310a991b8bada7b7c3a41be955621d9aaa023b9651ddf680e948c78d531b23012d307a0a48720a137d09c30e416387f5cfcde2d3da0a38b6049b87d072372bc62322355c5ab1e21b40b8bc44eb26773172add3fe750b11430c079cd83f06bad49f1c54ae184fc832c78a8f91e4121cf447421af48f06d3af160b4655895150fbbcad62a166ebc138389035b7b084d2aaa96c58e0c0592d36e16efd439081715ef64608eaf4a2c7314c728e573474a17a4dfe7fca1d0410a0e114050d960984858e77767ca72fb7a5129d748076df44a24e2c0c2882a420b436d60083d1879e31b727245fa6923273ca41f72445904a44af574254e6ba01ea2836d1450cc431fc131e795c2af2b7b278a6507564e55b4f9afa13687f362f6062f92faedb3ec88258104fa258a51a772899ed0e165734e8a1b54dba106ad568f2527eb8277024fa9903de8b531936ca8c43da8c222807787dd157dab5533790e98281d730d337a61ca093e34cf9ae771d41ac7570429b775f2501496c6420992552686f0d82c5dfb35db852f73f6e79eec30f2dee85dfd8cc7b9867578b41a4a4573ba2888bf122c1989bc8296434d2d1cde196f149aca2e0bdac9d7542287a3ee3ce024f7ff8189374832a500dfff8bbccd753cfa977bf3fdce743b3a4e521f389221b32412b06157e06aaba1e3b79c64d106f4df4d8d3bf59997c5f9c33a48b57c9eabd435cdf3365e2760f42660bfa9ee7a9ebcd6e82ed06ed8d0927ad66d592d9b7be340b51a341628fa45499f0cf862b8721cacc19a5035654001fd0521159fa0c963e08ba9c27b28ea26e98ae5276ae938f940dd4f884d896d69c0fe580e8ed092668bf2ef3f3768e3ad0dda32232aceece5d8733b463fccb63ec98f735c23a581572c70f8e60cca925f2c8a5de86d1485d047fb8c5bbd49b62795de64b40aa244cb472d2ccd18bd8eb141b2f15ccc029adfd1a1ffc4a28c89c5221a5e7072d7db3a9268ae47bd7d14c6fd787c3c54e2582f3019e7b9ac6b2c95bfb142849935e3f65e4cb37e342520021e318899b80cb53d127289976a670c6db65e2e87258d2d051c92eb8ebfb8e89f651983bffa5c5786f58537b7d')
parsed = GSSAPI.load(kerb5_auth_gssapi_2, strict = True)
parsed.debug()
pprint.pprint(parsed.native)


#server to client
kerb5_auth_gssapi_3 = bytes.fromhex('a181b53081b2a0030a0100a10b06092a864882f712010202a2819d04819a60819706092a864886f71201020202006f8187308184a003020105a10302010fa2783076a003020112a26f046d1c984dccd970dac7b140ff6901ced969cb2979cd16aee5ded0c930c11f57fd1543dcdec2defb7f5f565c619d336ab86d4bd4a89c628dd871e8a9c9b2c31836bdd7565297bfd39ed11548d79b22db3c4cebf597df677e18fcaad58680b1258c8cf67a3d10a0c32d44344dedcfe6')
parsed = NegotiationToken.load(kerb5_auth_gssapi_3, strict = True)
parsed.debug()
pprint.pprint(parsed.native)

"""