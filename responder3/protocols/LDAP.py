#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

# https://tools.ietf.org/html/rfc4511
# https://msdn.microsoft.com/en-us/library/cc223501.aspx
# https://ldap3.readthedocs.io/bind.html

from asn1crypto import core
import enum
import os

from responder3.core.commons import *
from responder3.core.asyncio_helpers import *

TAG = 'explicit'

# class
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2

class resultCode(core.Enumerated):
	_map = {
		0   : 'success',
        1  : 'operationsError',
        2  : 'protocolError',
        3  : 'timeLimitExceeded',
        4  : 'sizeLimitExceeded',
        5  : 'compareFalse',
        6  : 'compareTrue',
        7  : 'authMethodNotSupported',
        8  : 'strongerAuthRequired',
        10 : 'referral',
        11 : 'adminLimitExceeded',
        12 : 'unavailableCriticalExtension',
        13 : 'confidentialityRequired',
        14 : 'saslBindInProgress',
        16 : 'noSuchAttribute',
        17 : 'undefinedAttributeType',
        18 : 'inappropriateMatching',
        19 : 'constraintViolation',
        20 : 'attributeOrValueExists',
        21 : 'invalidAttributeSyntax',
        32 : 'noSuchObject',
        33 : 'aliasProblem',
        34 : 'invalidDNSyntax',
        36 : 'aliasDereferencingProblem',
        48 : 'inappropriateAuthentication',
        49 : 'invalidCredentials',
        50 : 'insufficientAccessRights',
        51 : 'busy',
        52 : 'unavailable',
        53 : 'unwillingToPerform',
        54 : 'loopDetect',
        64 : 'namingViolation',
        65 : 'objectClassViolation',
        66 : 'notAllowedOnNonLeaf',
        67 : 'notAllowedOnRDN',
        68 : 'entryAlreadyExists',
        69 : 'objectClassModsProhibited',
        71 : 'affectsMultipleDSAs',
        80 : 'other',
	}
	
	
class LDAPString(core.OctetString):
	pass
	
class LDAPDN(core.OctetString):
	pass
	
class LDAPOID(core.OctetString):
	pass
	
class URI(LDAPString):
	pass
	
class Referral(core.SequenceOf):
	_child_spec = URI

class Control(core.Sequence):
	_fields = [
		('controlType', LDAPOID, {'tag_type': TAG, 'tag': 0}),
		('criticality', core.Boolean, {'tag_type': TAG, 'tag': 1}),
		('controlValue', core.OctetString, {'tag_type': TAG, 'tag': 2, 'optional': True}),	
	]
	
class Controls(core.SequenceOf):
	_child_spec = Control
	
class SaslCredentials(core.Sequence):
	_fields = [
		('mechanism', LDAPString),
		('credentials', core.OctetString, {'optional': True}),	
	]
	
class SicilyPackageDiscovery(core.OctetString):
	pass

class SicilyNegotiate(core.OctetString):
	pass

class SicilyResponse(core.OctetString):
	pass
	
class AuthenticationChoice(core.Choice):
	_alternatives = [
		('simple', core.OctetString, {'implicit': (CONTEXT, 0)}),
		('sasl', SaslCredentials, {'implicit': (CONTEXT, 3)}),
		('sicily_disco', SicilyPackageDiscovery, {'implicit': (CONTEXT, 9)}), # FUCK
		('sicily_nego', SicilyNegotiate, {'implicit': (CONTEXT, 10)}), #YOU
		('sicily_resp', SicilyResponse, {'implicit': (CONTEXT, 11)}), #MICROSOFT
	]

class BindRequest(core.Sequence):
	_fields = [
		('version', core.Integer),
		('name', core.OctetString),
		('authentication', AuthenticationChoice),	
	]
	
class BindResponse(core.Sequence):
	_fields = [
		('resultCode', resultCode),
		('matchedDN', LDAPDN),
		('diagnosticMessage', LDAPString),
		('referral', Referral, {'optional': True}),
		('serverSaslCreds', core.OctetString, {'optional': True}),
	]

class protocolOp(core.Choice):
	_alternatives = [
		('bindRequest', BindRequest, {'implicit': (APPLICATION , 0) }  ),
		('bindResponse', BindResponse, {'implicit': (APPLICATION , 1) }  ),
		#('unbindRequest', UnbindRequest, {'implicit': (APPLICATION,0) }  ),
		#('searchRequest', SearchRequest, {'implicit': (APPLICATION,0) }  ),
		#('searchResEntry', searchResEntry, {'implicit': (APPLICATION,0) }  ),
		#('searchResDone', SearchResultDone, {'implicit': (APPLICATION,0) }  ),
		#('searchResRef', SearchResultReference, {'implicit': (APPLICATION,0) }  ),
		#('modifyRequest', ModifyRequest, {'implicit': (APPLICATION,0) }  ),
		#('modifyResponse', ModifyResponse, {'implicit': (APPLICATION,0) }  ),
		#('addRequest', AddRequest, {'implicit': (APPLICATION,0) }  ),
		#('addResponse', AddResponse, {'implicit': (APPLICATION,0) }  ),
		#('delRequest', DelRequest, {'implicit': (APPLICATION,0) }  ),
		#('delResponse', DelResponse, {'implicit': (APPLICATION,0) }  ),
		#('modDNRequest', ModifyDNRequest, {'implicit': (APPLICATION,0) }  ),
		#('modDNResponse', ModifyDNResponse, {'implicit': (APPLICATION,0) }  ),
		#('compareRequest', CompareRequest, {'implicit': (APPLICATION,0) }  ),
		#('compareResponse', CompareResponse, {'implicit': (APPLICATION,0) }  ),
		#('abandonRequest', AbandonRequest, {'implicit': (APPLICATION,0) }  ),
		#('extendedReq', ExtendedRequest, {'implicit': (APPLICATION,0) }  ),
		#('abandonRequest', AbandonRequest, {'implicit': (APPLICATION,0) }  ),
		#('extendedResp', ExtendedResponse, {'implicit': (APPLICATION,0) }  ),
	]
	
class LDAPMessage(core.Sequence):
	_fields = [
		('messageID', core.Integer),
		('protocolOp', protocolOp),
		('controls', Controls, {'implicit': (CONTEXT, 0), 'optional': True}),	
	]
	
class LDAPResult(core.Sequence):
	_fields = [
		('resultCode', resultCode ),
		('matchedDN', LDAPDN),
		('diagnosticMessage', LDAPString),
		('referral', Referral,  {'implicit': (CONTEXT, 3), 'optional': True}),
	]

class LdapParser:
	def __init__(self):
		pass
	
	@staticmethod
	async def from_streamreader(reader):
		preread = 6
		lb = await readexactly_or_exc(reader, preread)
		
		remaining_length = LdapParser.calcualte_length(lb) - preread
		remaining_data = await readexactly_or_exc(reader, remaining_length)
		
		message = LDAPMessage.load(lb+remaining_data)
		
		return message
		
	def calcualte_length(data):
		"""
		LDAP protocol doesnt send the total length of the message in the header,
		it only sends raw ASN1 encoded data structures, which has the length encoded.
		This function "decodes" the length os the asn1 structure, and returns it as int.
		"""
		if data[1] <= 127:
			return data[1] + 2
		else:
			bcount = data[1] - 128
			if (bcount +2 ) > len(data):
				raise Exception('LDAP data too larage! Length byte count: %s' % bcount)
			return int.from_bytes(data[2:2+bcount], byteorder = 'big', signed = False) + bcount + 2
			

