from asn1crypto.core import ObjectIdentifier,Choice, Any, SequenceOf, BitString, Sequence, GeneralString, OctetString, Enumerated

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
		('hintName', GeneralString, {'optional': True}),
		('hintAddress', OctetString, {'optional': True}),
]

class NegTokenInit2(Sequence):

	_fields = [
		('mechTypes', MechTypes, {'optional': True}),
		('reqFlags', ContextFlags, {'optional': True}),
		('mechToken', OctetString, {'optional': True}),
		('mechListMIC', OctetString, {'optional': True}),
		('negHints', NegHints, {'optional': True}),
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
		('negState', negState, {'optional': True}),
		('supportedMech', MechType, {'optional': True}),
		('responseToken', OctetString, {'optional': True}),
		('mechListMIC', OctetString, {'optional': True}),
]

class NegotiationToken(Choice):
	_alternatives = [
		('NegTokenInit2', NegTokenInit2),
		('negTokenResp', negTokenResp),
	]



class SPNEGO(Sequence):
	#explicit_class = APPLICATION

	_fields = [
		('NegotiationToken', NegotiationToken),
]

class GSSType(ObjectIdentifier):
	_map = { 
		#'': 'SNMPv2-SMI::enterprises.311.2.2.30',
		'1.3.6.1.5.5.2': 'SPNEGO',
	}

class GSSAPI(Sequence):
	_fields = [
		('type', GSSType),
		('value', Any),
	]

	_oid_pair = ('type', 'value')
	_oid_specs = {
		'SPNEGO': SPNEGO,
	}



#ExtensionId._map['1.3.6.1.5.5.2'] = 'SPNEGO - Simple Protected Negotiation'
##Extension._oid_specs['SPNEGO - Simple Protected Negotiation'] = GSSAPI
#
#if __name__ == '__main__':
#
data = bytes.fromhex('605e06062b0601050502a0543052a024302206092a864882f71201020206092a864886f712010202060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265')
print(data)
parsed = GSSAPI.load(data)
parsed.debug()