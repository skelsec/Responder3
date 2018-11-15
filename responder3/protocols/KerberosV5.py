#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

# https://zeroshell.org/kerberos/kerberos-operation/

from asn1crypto import core
import enum
import os

from responder3.core.commons import *
from responder3.core.logging.log_objects import Credential
from responder3.core.asyncio_helpers import *

# KerberosV5Spec2 DEFINITIONS EXPLICIT TAGS ::=
TAG = 'explicit'

# class
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2
krb5_pvno = 5 #-- current Kerberos protocol version number

"""
class NegotiationToken(core.Choice):
	_alternatives = [
		#('NegTokenInit2', NegTokenInit2, {'implicit': (0,16) }  ), #NegTokenInit2 the '2' in the name is because Microsoft added modifications to the original rfc :)
		('NegTokenInit2', NegTokenInit2, {'implicit': (0,16) }  ), #NegTokenInit2 the '2' in the name is because Microsoft added modifications to the original rfc :)
		('negTokenResp', negTokenResp, {'explicit': (2,1) } ),
		
]
"""

class NAME_TYPE(enum.Enum):
	UNKNOWN = 0     #(0),	-- Name type not known
	PRINCIPAL = 1     #(1),	-- Just the name of the principal as in
	SRV_INST = 2     #(2),	-- Service and other unique instance (krbtgt)
	SRV_HST = 3     #(3),	-- Service with host name as instance
	SRV_XHST = 4     # (4),	-- Service with host as remaining components
	UID = 5     # (5),		-- Unique ID
	X500_PRINCIPAL = 6     #(6), -- PKINIT
	SMTP_NAME = 7     #(7),	-- Name in form of SMTP email name
	ENTERPRISE_PRINCIPAL = 10    #(10), -- Windows 2000 UPN
	WELLKNOWN  = 11    #(11),	-- Wellknown
	ENT_PRINCIPAL_AND_ID  = -130  #(-130), -- Windows 2000 UPN and SID
	MS_PRINCIPAL = -128  #(-128), -- NT 4 style name
	MS_PRINCIPAL_AND_ID = -129  #(-129), -- NT style name and SID
	NTLM = -1200 #(-1200) -- NTLM name, realm is domain

class MESSAGE_TYPE(enum.Enum):
	KRB_AS_REQ = 10 
	KRB_AS_REP = 11 
	KRB_TGS_REQ = 12 
	KRB_TGS_REP = 13 
	KRB_AP_REQ = 14 
	KRB_AP_REP = 15 
	KRB_SAFE = 20 
	KRB_PRIV = 21 
	KRB_CRED = 22 
	KRB_ERROR = 30 

class EncryptionType(enum.Enum):
	NULL = 0#
	DES_CBC_CRC = 1#
	DES_CBC_MD4 = 2#
	DES_CBC_MD5 = 3#
	DES3_CBC_MD5 = 5#
	OLD_DES3_CBC_SHA1 = 7#
	SIGN_DSA_GENERATE = 8#
	ENCRYPT_RSA_PRIV = 9#
	ENCRYPT_RSA_PUB = 10#
	DES3_CBC_SHA1 = 16#	-- with key derivation
	AES128_CTS_HMAC_SHA1_96 = 17#
	AES256_CTS_HMAC_SHA1_96 = 18#
	ARCFOUR_HMAC_MD5 = 23#
	ARCFOUR_HMAC_MD5_56 = 24#
	ENCTYPE_PK_CROSS = 48#
	ARCFOUR_MD4 = -128#
	ARCFOUR_HMAC_OLD = -133#
	ARCFOUR_HMAC_OLD_EXP = -135#
	DES_CBC_NONE = -0x1000#
	DES3_CBC_NONE = -0x1001#
	DES_CFB64_NONE = -0x1002#
	DES_PCBC_NONE = -0x1003#
	DIGEST_MD5_NONE = -0x1004#		-- private use, lukeh@padl.com
	CRAM_MD5_NONE = -0x1005#		-- private use, lukeh@padl.com
	
	
class PaDataType(enum.Enum):
	NONE = 0#
	TGS_REQ = 1#
	AP_REQ = 1#
	ENC_TIMESTAMP = 2#
	PW_SALT = 3#
	ENC_UNIX_TIME = 5#
	SANDIA_SECUREID = 6#
	SESAME = 7#
	OSF_DCE = 8#
	CYBERSAFE_SECUREID = 9#
	AFS3_SALT = 10#
	ETYPE_INFO = 11#
	SAM_CHALLENGE = 12# __  = sam/otp)
	SAM_RESPONSE = 13# __  = sam/otp)
	PK_AS_REQ_19 = 14# __  = PKINIT_19)
	PK_AS_REP_19 = 15# __  = PKINIT_19)
	PK_AS_REQ_WIN = 15# __  = PKINIT _ old number)
	PK_AS_REQ = 16# __  = PKINIT_25)
	PK_AS_REP = 17# __  = PKINIT_25)
	PA_PK_OCSP_RESPONSE = 18#
	ETYPE_INFO2 = 19#
	USE_SPECIFIED_KVNO = 20#
	SVR_REFERRAL_INFO = 20# ___ old ms referral number
	SAM_REDIRECT = 21# __  = sam/otp)
	GET_FROM_TYPED_DATA = 22#
	SAM_ETYPE_INFO = 23#
	SERVER_REFERRAL = 25#
	ALT_PRINC = 24#		__  = crawdad@fnal.gov)
	SAM_CHALLENGE2 = 30#		__  = kenh@pobox.com)
	SAM_RESPONSE2 = 31#		__  = kenh@pobox.com)
	PA_EXTRA_TGT = 41#			__ Reserved extra TGT
	TD_KRB_PRINCIPAL = 102#	__ PrincipalName
	PK_TD_TRUSTED_CERTIFIERS = 104# __ PKINIT
	PK_TD_CERTIFICATE_INDEX = 105# __ PKINIT
	TD_APP_DEFINED_ERROR = 106#	__ application specific
	TD_REQ_NONCE = 107#		__ INTEGER
	TD_REQ_SEQ = 108#		__ INTEGER
	PA_PAC_REQUEST = 128#	__ jbrezak@exchange.microsoft.com
	FOR_USER = 129#		__ MS_KILE
	FOR_X509_USER = 130#		__ MS_KILE
	FOR_CHECK_DUPS = 131#	__ MS_KILE
	AS_CHECKSUM = 132#		__ MS_KILE
	PK_AS_09_BINDING = 132#	__ client send this to __ tell KDC that is supports __ the asCheckSum in the __  PK_AS_REP
	CLIENT_CANONICALIZED = 133#	__ referals
	FX_COOKIE = 133#		__ krb_wg_preauth_framework
	AUTHENTICATION_SET = 134#	__ krb_wg_preauth_framework
	AUTH_SET_SELECTED = 135#	__ krb_wg_preauth_framework
	FX_FAST = 136#		__ krb_wg_preauth_framework
	FX_ERROR = 137#		__ krb_wg_preauth_framework
	ENCRYPTED_CHALLENGE = 138#	__ krb_wg_preauth_framework
	OTP_CHALLENGE = 141#		__  = gareth.richards@rsa.com)
	OTP_REQUEST = 142#		__  = gareth.richards@rsa.com)
	OTP_CONFIRM = 143#		__  = gareth.richards@rsa.com)
	OTP_PIN_CHANGE = 144#	__  = gareth.richards@rsa.com)
	EPAK_AS_REQ = 145#
	EPAK_AS_REP = 146#
	PKINIT_KX = 147#		__ krb_wg_anon
	PKU2U_NAME = 148#		__ zhu_pku2u
	REQ_ENC_PA_REP = 149#	__
	SUPPORTED_ETYPES = 165 #)	__ MS_KILE
	
class PADATA_TYPE(core.Enumerated):
	_map = {
		0   : 'NONE', #(0),
		1   : 'TGS-REQ', #(1),
		1   : 'AP-REQ', #(1),
		2   : 'ENC-TIMESTAMP', #(2),
		3   : 'PW-SALT', #(3),
		5   : 'ENC-UNIX-TIME', #(5),
		6   : 'SANDIA-SECUREID', #(6),
		7   : 'SESAME', #(7),
		8   : 'OSF-DCE', #(8),
		9   : 'CYBERSAFE-SECUREID', #(9),
		10  : 'AFS3-SALT', #(10),
		11  : 'ETYPE-INFO', #(11),
		12  : 'SAM-CHALLENGE', #(12), -- ', #(sam/otp)
		13  : 'SAM-RESPONSE', #(13), -- ', #(sam/otp)
		14  : 'PK-AS-REQ-19', #(14), -- ', #(PKINIT-19)
		15  : 'PK-AS-REP-19', #(15), -- ', #(PKINIT-19)
		15  : 'PK-AS-REQ-WIN', #(15), -- ', #(PKINIT - old number)
		16  : 'PK-AS-REQ', #(16), -- ', #(PKINIT-25)
		17  : 'PK-AS-REP', #(17), -- ', #(PKINIT-25)
		18  : 'PA-PK-OCSP-RESPONSE', #(18),
		19  : 'ETYPE-INFO2', #(19),
		20  : 'USE-SPECIFIED-KVNO', #(20),
		20  : 'SVR-REFERRAL-INFO', #(20), --- old ms referral number
		21  : 'SAM-REDIRECT', #(21), -- ', #(sam/otp)
		22  : 'GET-FROM-TYPED-DATA', #(22),
		23  : 'SAM-ETYPE-INFO', #(23),
		25  : 'SERVER-REFERRAL', #(25),
		24  : 'ALT-PRINC', #(24),		-- ', #(crawdad@fnal.gov)
		30  : 'SAM-CHALLENGE2', #(30),		-- ', #(kenh@pobox.com)
		31  : 'SAM-RESPONSE2', #(31),		-- ', #(kenh@pobox.com)
		41  : 'PA-EXTRA-TGT', #(41),			-- Reserved extra TGT
		102 : 'TD-KRB-PRINCIPAL', #(102),	-- PrincipalName
		104 : 'PK-TD-TRUSTED-CERTIFIERS', #(104), -- PKINIT
		105 : 'PK-TD-CERTIFICATE-INDEX', #(105), -- PKINIT
		106 : 'TD-APP-DEFINED-ERROR', #(106),	-- application specific
		107 : 'TD-REQ-NONCE', #(107),		-- INTEGER
		108 : 'TD-REQ-SEQ', #(108),		-- INTEGER
		128 : 'PA-PAC-REQUEST', #(128),	-- jbrezak@exchange.microsoft.com
		129 : 'FOR-USER', #(129),		-- MS-KILE
		130 : 'FOR-X509-USER', #(130),		-- MS-KILE
		131 : 'FOR-CHECK-DUPS', #(131),	-- MS-KILE
		132 : 'AS-CHECKSUM', #(132),		-- MS-KILE
		132 : 'PK-AS-09-BINDING', #(132),	-- client send this to -- tell KDC that is supports -- the asCheckSum in the --  PK-AS-REP
		133 : 'CLIENT-CANONICALIZED', #(133),	-- referals
		133 : 'FX-COOKIE', #(133),		-- krb-wg-preauth-framework
		134 : 'AUTHENTICATION-SET', #(134),	-- krb-wg-preauth-framework
		135 : 'AUTH-SET-SELECTED', #(135),	-- krb-wg-preauth-framework
		136 : 'FX-FAST', #(136),		-- krb-wg-preauth-framework
		137 : 'FX-ERROR', #(137),		-- krb-wg-preauth-framework
		138 : 'ENCRYPTED-CHALLENGE', #(138),	-- krb-wg-preauth-framework
		141 : 'OTP-CHALLENGE', #(141),		-- ', #(gareth.richards@rsa.com)
		142 : 'OTP-REQUEST', #(142),		-- ', #(gareth.richards@rsa.com)
		143 : 'OTP-CONFIRM', #(143),		-- ', #(gareth.richards@rsa.com)
		144 : 'OTP-PIN-CHANGE', #(144),	-- ', #(gareth.richards@rsa.com)
		145 : 'EPAK-AS-REQ', #(145),
		146 : 'EPAK-AS-REP', #(146),
		147 : 'PKINIT-KX', #(147),		-- krb-wg-anon
		148 : 'PKU2U-NAME', #(148),		-- zhu-pku2u
		149 : 'REQ-ENC-PA-REP', #(149),	--
		165 : 'SUPPORTED-ETYPES', #(165)	-- MS-KILE
	}
	
class AUTHDATA_TYPE(core.Enumerated):
	_map = {
		1 : 'IF-RELEVANT', #1),
		2 : 'INTENDED-FOR_SERVER', #2),
		3 : 'INTENDED-FOR-APPLICATION-CLASS', #3),
		4 : 'KDC-ISSUED', #4),
		5 : 'AND-OR', #5),
		6 : 'MANDATORY-TICKET-EXTENSIONS', #6),
		7 : 'IN-TICKET-EXTENSIONS', #7),
		8 : 'MANDATORY-FOR-KDC', #8),
		9 : 'INITIAL-VERIFIED-CAS', #9),
		64 : 'OSF-DCE', #64),
		65 : 'SESAME', #65),
		66 : 'OSF-DCE-PKI-CERTID', #66),
		128 : 'WIN2K-PAC', #128),
		129 : 'GSS-API-ETYPE-NEGOTIATION', #129), -- Authenticator only
		-17 : 'SIGNTICKET-OLDER', #-17),
		142 : 'SIGNTICKET-OLD', #142),
		512 : 'SIGNTICKET', #512)
	}

class CKSUMTYPE(core.Enumerated):
	_map = {
		0 : 'NONE', #0),
		1 : 'CRC32', #1),
		2 : 'RSA_MD4', #2),
		3 : 'RSA_MD4_DES', #3),
		4 : 'DES_MAC', #4),
		5 : 'DES_MAC_K', #5),
		6 : 'RSA_MD4_DES_K', #6),
		7 : 'RSA_MD5', #7),
		8 : 'RSA_MD5_DES', #8),
		9 : 'RSA_MD5_DES3', #9),
		10 : 'SHA1_OTHER', #10),
		12 : 'HMAC_SHA1_DES3', #12),
		14 : 'SHA1', #14),
		15 : 'HMAC_SHA1_96_AES_128', #15),
		16 : 'HMAC_SHA1_96_AES_256', #16),
		0x8003 : 'GSSAPI', #0x8003),
		-138 : 'HMAC_MD5', #-138),	-- unofficial microsoft number
		-1138 : 'HMAC_MD5_ENC', #-1138)	-- even more unofficial
	}

#enctypes
class ENCTYPE(core.Enumerated):
	_map = {
		0 : 'NULL', #0),
		1 : 'DES_CBC_CRC', #1),
		2 : 'DES_CBC_MD4', #2),
		3 : 'DES_CBC_MD5', #3),
		5 : 'DES3_CBC_MD5', #5),
		7 : 'OLD_DES3_CBC_SHA1', #7),
		8 : 'SIGN_DSA_GENERATE', #8),
		9 : 'ENCRYPT_RSA_PRIV', #9),
		10 : 'ENCRYPT_RSA_PUB', #10),
		16 : 'DES3_CBC_SHA1', #16),	-- with key derivation
		17 : 'AES128_CTS_HMAC_SHA1_96', #17),
		18 : 'AES256_CTS_HMAC_SHA1_96', #18),
		23 : 'ARCFOUR_HMAC_MD5', #23),
		24 : 'ARCFOUR_HMAC_MD5_56', #24),
		48 : 'ENCTYPE_PK_CROSS', #48),
		#-- some "old" windows types
		-128 : 'ARCFOUR_MD4', #-128),
		-133 : 'ARCFOUR_HMAC_OLD', #-133),
		-135 : 'ARCFOUR_HMAC_OLD_EXP', #-135),
		#-- these are for Heimdal internal use
		-0x1000 : 'DES_CBC_NONE', #-0x1000),
		-0x1001 : 'DES3_CBC_NONE', #-0x1001),
		-0x1002 : 'DES_CFB64_NONE', #-0x1002),
		-0x1003 : 'DES_PCBC_NONE', #-0x1003),
		-0x1004 : 'DIGEST_MD5_NONE', #-0x1004),		-- private use, lukeh@padl.com
		-0x1005 : 'CRAM_MD5_NONE', #-0x1005)		-- private use, lukeh@padl.com
	}
	
class SequenceOfEnctype(core.SequenceOf):
	_child_spec = core.Integer

class Microseconds(core.Integer):
	"""    ::= INTEGER (0..999999)
	-- microseconds
    """      
class krb5int32 (core.Integer):
    """krb5int32  ::= INTEGER (-2147483648..2147483647)
    """


class krb5uint32 (core.Integer):
    """krb5uint32  ::= INTEGER (0..4294967295)
    """

class KerberosString(core.GeneralString):
	"""KerberosString ::= GeneralString (IA5String)
	For compatibility, implementations MAY choose to accept GeneralString
	values that contain characters other than those permitted by
	IA5String...
	"""
	
class SequenceOfKerberosString(core.SequenceOf):
	_child_spec = KerberosString
	
# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class Realm(KerberosString):
	"""Realm ::= KerberosString
	"""

	
# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class PrincipalName(core.Sequence):
	"""PrincipalName for KDC-REQ-BODY and Ticket
	PrincipalName ::= SEQUENCE {
		name-type	[0] Int32,
		name-string  [1] SEQUENCE OF KerberosString
	}
	"""
	_fields = [
		('name-type', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('name-string', SequenceOfKerberosString, {'tag_type': TAG, 'tag': 1}),
	]
	
	
class Principal(core.Sequence):
	_fields = [
		('name', PrincipalName, {'tag_type': TAG, 'tag': 0}),
		('realm', Realm, {'tag_type': TAG, 'tag': 1}),
	]

	
class Principals(core.SequenceOf):
	_child_spec = Principal

	
class HostAddress(core.Sequence):
    """HostAddress for HostAddresses
    HostAddress ::= SEQUENCE {
        addr-type        [0] Int32,
        address  [1] OCTET STRING
    }
    """
    _fields = [
        ('addr-type', krb5int32, {'tag_type': TAG, 'tag': 0}),
        ('address', core.OctetString, {'tag_type': TAG, 'tag': 1}),
]


class HostAddresses(core.SequenceOf):
	"""SEQUENCE OF HostAddress
	"""
	_child_spec = HostAddress
	
	
class KerberosTime(core.GeneralizedTime):
    """KerberosTime ::= GeneralizedTime
    """

	
class AuthorizationDataElement(core.SequenceOf):
	_fields = [
        ('ad-type', krb5int32, {'tag_type': TAG, 'tag': 0}),
        ('ad-data', core.OctetString, {'tag_type': TAG, 'tag': 1}),
	]

	
class AuthorizationData(core.SequenceOf):
	"""SEQUENCE OF HostAddress
	"""
	_child_spec = AuthorizationDataElement
	

class APOptions(core.BitString):
	_map = {
		0 : 'reserved', #(0),
		1 : 'use-session-key', #(1),
		2 : 'mutual-required', #(2)
	}

	
class TicketFlags(core.BitString):
	_map = {
		0: 'reserved',
		1: 'forwardable',
		2: 'forwarded',
		3: 'proxiable',
		4: 'proxy',
		5: 'may-postdate',
		6: 'postdated',
		7: 'invalid',
		8: 'renewable',
		9: 'initial',
		10: 'pre-authent',
		11: 'hw-authent',
		12: 'transited-policy-checked',
		13: 'ok-as-delegate',
		14: 'anonymous',
		15: 'enc-pa-rep'
	}


class KDCOptions(core.BitString):
	_map = {
		0: 'reserved',
		1: 'forwardable',
		2: 'forwarded',
		3: 'proxiable',
		4: 'proxy',
		5: 'allow-postdate',
		6: 'postdated',
		7: 'unused7',
		8: 'renewable',
		9: 'unused9',
		10: 'unused10',
		11: 'opt-hardware-auth',
		12: 'unused12',
		13: 'unused13',
		14: 'constrained-delegation',
		15: 'canonicalize',
		16: 'request-anonymous',
		17: 'unused17',
		18: 'unused18',
		19: 'unused19',
		20: 'unused20',
		21: 'unused21',
		22: 'unused22',
		23: 'unused23',
		24: 'unused24',
		25: 'unused25',
		26: 'disable-transited-check',
		27: 'renewable-ok',
		28: 'enc-tkt-in-skey',
		30: 'renew',
		31: 'validate',
	}

class LR_TYPE(core.Enumerated):
	_map = {
		0 : 'NONE', #0),		-- no information
		1 : 'INITIAL_TGT', #1),	-- last initial TGT request
		2 : 'INITIAL', #2),		-- last initial request
		3 : 'ISSUE_USE_TGT', #3),	-- time of newest TGT used
		4 : 'RENEWAL', #4),		-- time of last renewal
		5 : 'REQUEST', #5),		-- time of last request ', #of any type)
		6 : 'PW_EXPTIME', #6),	-- expiration time of password
		7 : 'ACCT_EXPTIME', #7)	-- expiration time of account
	}
	
class LastReqInner(core.Sequence):
	_fields = [
		('lr-type', krb5int32, {'tag_type': TAG, 'tag': 0}), #LR_TYPE
		('lr-value', KerberosTime, {'tag_type': TAG, 'tag': 1}),
	]

class LastReq(core.SequenceOf):
	_child_spec = LastReqInner


class EncryptedData(core.Sequence):
	_fields = [
		('etype', krb5int32, {'tag_type': TAG, 'tag': 0}), #-- EncryptionType
		('kvno', krb5uint32, {'tag_type': TAG, 'tag': 1, 'optional': True}), #
		('cipher', core.OctetString, {'tag_type': TAG, 'tag': 2}), #ciphertext
	]


class EncryptionKey(core.Sequence):
	_fields = [
		('keytype', krb5uint32, {'tag_type': TAG, 'tag': 0}), #-- EncryptionType
		('keyvalue', core.OctetString, {'tag_type': TAG, 'tag': 1}), #
	]


#-- encoded Transited field

class TransitedEncoding(core.Sequence):
	_fields = [
		('tr-type', krb5uint32, {'tag_type': TAG, 'tag': 0}), #-- must be registered
		('contents', core.OctetString, {'tag_type': TAG, 'tag': 1}), #
	]



# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class Ticket(core.Sequence):
	explicit = (APPLICATION,1)
	
	_fields = [
		('tkt-vno', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('realm', Realm, {'tag_type': TAG, 'tag': 1}),
		('sname', PrincipalName, {'tag_type': TAG, 'tag': 2}),
		('enc-part', EncryptedData, {'tag_type': TAG, 'tag': 3}), #EncTicketPart
	]
	
class SequenceOfTicket(core.SequenceOf):
	"""SEQUENCE OF Ticket for KDC-REQ-BODY
	"""
	_child_spec = Ticket


#-- Encrypted part of ticket
class EncTicketPart(core.Sequence):
	explicit = (APPLICATION,3)
	
	_fields = [
		('flags', TicketFlags, {'tag_type': TAG, 'tag': 0}),
		('key', EncryptionKey, {'tag_type': TAG, 'tag': 1}),
		('crealm', Realm, {'tag_type': TAG, 'tag': 2}),
		('cname', PrincipalName, {'tag_type': TAG, 'tag': 3}),
		('transited', TransitedEncoding, {'tag_type': TAG, 'tag': 4}),
		('authtime', KerberosTime, {'tag_type': TAG, 'tag': 5}),
		('starttime', KerberosTime, {'tag_type': TAG, 'tag': 6, 'optional': True}),
		('endtime', KerberosTime, {'tag_type': TAG, 'tag': 7}),
		('renew-till', KerberosTime, {'tag_type': TAG, 'tag': 8, 'optional': True}),
		('caddr', HostAddresses, {'tag_type': TAG, 'tag': 9, 'optional': True}),
		('authorization-data', AuthorizationData, {'tag_type': TAG, 'tag': 10, 'optional': True}),
	]


class Checksum(core.Sequence):
	_fields = [
		('cksumtype', CKSUMTYPE, {'tag_type': TAG, 'tag': 0}),
		('checksum', core.OctetString, {'tag_type': TAG, 'tag': 1}),
	]


class Authenticator(core.Sequence):
	explicit = (APPLICATION,2)
	
	_fields = [
		('authenticator-vno', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('crealm', Realm, {'tag_type': TAG, 'tag': 1}),
		('cname', PrincipalName, {'tag_type': TAG, 'tag': 2}),
		('cksum', Checksum, {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('cusec', krb5int32, {'tag_type': TAG, 'tag': 4}),
		('ctime', KerberosTime, {'tag_type': TAG, 'tag': 5}),
		('subkey', EncryptionKey, {'tag_type': TAG, 'tag': 6, 'optional': True}),
		('seq-number', krb5uint32, {'tag_type': TAG, 'tag': 7, 'optional': True}),
		('authorization-data', AuthorizationData, {'tag_type': TAG, 'tag': 8, 'optional': True}),
	]


class PA_DATA(core.Sequence): #!!!! IT STARTS AT ONE!!!!
	_fields = [
		('padata-type', core.Integer, {'tag_type': TAG, 'tag': 1}),
		('padata-value', core.OctetString, {'tag_type': TAG, 'tag': 2}),
	]
	
class ETYPE_INFO_ENTRY(core.Sequence):
	_fields = [
		('etype', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('salt', core.OctetString, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('salttype', krb5int32, {'tag_type': TAG, 'tag': 2, 'optional': True}),
	]

class ETYPE_INFO(core.SequenceOf):
	_child_spec = ETYPE_INFO_ENTRY


class ETYPE_INFO2_ENTRY(core.Sequence):
	_fields = [
		('etype', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('salt', KerberosString, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('s2kparams', core.OctetString, {'tag_type': TAG, 'tag': 2, 'optional': True}),
	]
	
class ETYPE_INFO2(core.SequenceOf):
	_child_spec = ETYPE_INFO2_ENTRY

class METHOD_DATA(core.SequenceOf):
	_child_spec = PA_DATA


class TypedData(core.Sequence):
	_fields = [
		('data-type', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('data-value', core.OctetString, {'tag_type': TAG, 'tag': 1, 'optional': True}),
	]

"""
class TYPED-DATA ::= SEQUENCE SIZE (1..MAX) OF TypedData
"""


class KDC_REQ_BODY(core.Sequence):
	_fields = [
		('kdc-options', KDCOptions, {'tag_type': TAG, 'tag': 0}),
		('cname', PrincipalName, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('realm', Realm, {'tag_type': TAG, 'tag': 2}),
		('sname', PrincipalName , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('from', KerberosTime , {'tag_type': TAG, 'tag': 4, 'optional': True}),
		('till', KerberosTime , {'tag_type': TAG, 'tag': 5, 'optional': True}),
		('rtime', KerberosTime , {'tag_type': TAG, 'tag': 6, 'optional': True}),
		('nonce', krb5int32 , {'tag_type': TAG, 'tag': 7}),
		('etype', SequenceOfEnctype , {'tag_type': TAG, 'tag': 8}), # -- EncryptionType,preference order
		('addresses', HostAddresses , {'tag_type': TAG, 'tag': 9, 'optional': True}),
		('enc-authorization-data', EncryptedData , {'tag_type': TAG, 'tag': 10, 'optional': True}), #-- Encrypted AuthorizationData encoding
		('additional-tickets', SequenceOfTicket , {'tag_type': TAG, 'tag': 11, 'optional': True}),
	
	]

class KDC_REQ(core.Sequence):
	_fields = [
		('pvno', krb5int32, {'tag_type': TAG, 'tag': 1}),
		('msg-type', krb5int32, {'tag_type': TAG, 'tag': 2}), #MESSAGE_TYPE
		('padata', METHOD_DATA , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('req-body', KDC_REQ_BODY , {'tag_type': TAG, 'tag': 4}),
	]


class AS_REQ(KDC_REQ):
	explicit = (APPLICATION, 10)
	
class TGS_REQ(KDC_REQ):
	explicit = (APPLICATION, 12)


#-- padata-type ::= PA-ENC-TIMESTAMP
#-- padata-value ::= EncryptedData - PA-ENC-TS-ENC

class PA_ENC_TS_ENC(core.Sequence):
	_fields = [
		('patimestamp', KerberosTime, {'tag_type': TAG, 'tag': 0}), #-- client's time
		('pausec', krb5int32, {'tag_type': TAG, 'tag': 1, 'optional':True}),
	]

#-- draft-brezak-win2k-krb-authz-01
class PA_PAC_REQUEST(core.Sequence):
	_fields = [
		('include-pac', core.Boolean, {'tag_type': TAG, 'tag': 0}), #-- Indicates whether a PAC should be included or not
	]

#-- PacketCable provisioning server location, PKT-SP-SEC-I09-030728.pdf
class PROV_SRV_LOCATION(core.GeneralString):
	pass


class KDC_REP(core.Sequence):
	_fields = [
		('pvno', core.Integer, {'tag_type': TAG, 'tag': 0}),
		('msg-type', krb5int32, {'tag_type': TAG, 'tag': 1}), #MESSAGE_TYPE
		('padata', METHOD_DATA, {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('crealm', Realm , {'tag_type': TAG, 'tag': 3}),
		('cname', PrincipalName , {'tag_type': TAG, 'tag': 4}),
		('ticket', Ticket , {'tag_type': TAG, 'tag': 5}),
		('enc-part', EncryptedData , {'tag_type': TAG, 'tag': 6}), #EncKDCRepPart
	]
	

class AS_REP(KDC_REP):
	#::= [APPLICATION 11] KDC-REP
	explicit = (APPLICATION, 11)
	
class TGS_REP(KDC_REP): # ::= [APPLICATION 13] KDC-REP
	explicit = (APPLICATION, 13)
	
	
class EncKDCRepPart(core.Sequence):
	_fields = [
		('key', EncryptionKey, {'tag_type': TAG, 'tag': 0}),
		('last-req', LastReq, {'tag_type': TAG, 'tag': 1}),
		('nonce', krb5int32, {'tag_type': TAG, 'tag': 2}),
		('key-expiration', KerberosTime , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('flags', TicketFlags , {'tag_type': TAG, 'tag': 4}),
		('authtime', KerberosTime , {'tag_type': TAG, 'tag': 5}),
		('starttime', KerberosTime , {'tag_type': TAG, 'tag': 6, 'optional': True}),
		('endtime', KerberosTime , {'tag_type': TAG, 'tag': 7}),
		('renew-till', KerberosTime , {'tag_type': TAG, 'tag': 8, 'optional': True}),
		('srealm', Realm , {'tag_type': TAG, 'tag': 9}),
		('sname', PrincipalName , {'tag_type': TAG, 'tag': 10}),
		('caddr', HostAddresses , {'tag_type': TAG, 'tag': 11, 'optional': True}),
		('encrypted-pa-data', METHOD_DATA , {'tag_type': TAG, 'tag': 12, 'optional': True}),
	]

class EncASRepPart(EncKDCRepPart):
	explicit = (APPLICATION, 25)
	
class EncTGSRepPart(EncKDCRepPart):
	explicit = (APPLICATION, 26)



class AP_REQ(core.Sequence):
	explicit = (APPLICATION, 14)
	_fields = [
		('pvno', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('msg-type', krb5int32, {'tag_type': TAG, 'tag': 1}), #MESSAGE_TYPE
		('ap-options', APOptions, {'tag_type': TAG, 'tag': 2}),
		('ticket', Ticket , {'tag_type': TAG, 'tag': 3}),
		('authenticator', EncryptedData , {'tag_type': TAG, 'tag': 4}),
	]

class AP_REP(core.Sequence):
	explicit = (APPLICATION, 15)
	_fields = [
		('pvno', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('msg-type', krb5int32, {'tag_type': TAG, 'tag': 1}),#MESSAGE_TYPE
		('enc-part', EncryptedData , {'tag_type': TAG, 'tag': 2}),
	]


class EncAPRepPart(core.Sequence):
	explicit = (APPLICATION, 27)
	_fields = [
		('ctime', KerberosTime, {'tag_type': TAG, 'tag': 0}),
		('cusec', krb5int32, {'tag_type': TAG, 'tag': 1}),
		('subkey', EncryptionKey , {'tag_type': TAG, 'tag': 2}),
		('seq-number', krb5uint32 , {'tag_type': TAG, 'tag': 3, 'optional': True}),
	]


class KRB_SAFE_BODY(core.Sequence):
	_fields = [
		('user-data', core.OctetString, {'tag_type': TAG, 'tag': 0}),
		('timestamp', KerberosTime, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('usec', krb5int32 , {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('seq-number', krb5uint32 , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('s-address', HostAddress , {'tag_type': TAG, 'tag': 4, 'optional': True}),
		('r-address', HostAddress , {'tag_type': TAG, 'tag': 5, 'optional': True}),
	]


class KRB_SAFE(core.Sequence):
	explicit = (APPLICATION, 20)
	_fields = [
		('pvno', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('msg-type', krb5int32, {'tag_type': TAG, 'tag': 1}),#MESSAGE_TYPE
		('safe-body', KRB_SAFE_BODY , {'tag_type': TAG, 'tag': 2}),
		('cksum', Checksum , {'tag_type': TAG, 'tag': 3}),
	]

class KRB_PRIV(core.Sequence):
	explicit = (APPLICATION, 21)
	_fields = [
		('pvno', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('msg-type', krb5int32, {'tag_type': TAG, 'tag': 1}),#MESSAGE_TYPE
		('enc-part', EncryptedData, {'tag_type': TAG, 'tag': 2}),
	] 


class EncKrbPrivPart(core.Sequence):
	explicit = (APPLICATION, 28)
	_fields = [
		('user-data', core.OctetString, {'tag_type': TAG, 'tag': 0}),
		('timestamp', KerberosTime, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('usec', krb5int32 , {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('seq-number', krb5uint32 , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('s-address', HostAddress , {'tag_type': TAG, 'tag': 4, 'optional': True}),
		('r-address', HostAddress , {'tag_type': TAG, 'tag': 5, 'optional': True}),
	]


class KRB_CRED(core.Sequence):
	explicit = (APPLICATION, 22)
	_fields = [
		('pvno', core.Integer, {'tag_type': TAG, 'tag': 0}),
		('msg-type', core.Integer, {'tag_type': TAG, 'tag': 1}),
		('tickets', SequenceOfTicket, {'tag_type': TAG, 'tag': 2}),
		('enc-part', EncryptedData , {'tag_type': TAG, 'tag': 3}),
	
	]
	
# http://web.mit.edu/freebsd/head/crypto/heimdal/lib/asn1/krb5.asn1
class KrbCredInfo(core.Sequence):
	_fields = [
		('key', EncryptionKey, {'tag_type': TAG, 'tag': 0}),
		('prealm', Realm, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('pname', PrincipalName, {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('flags', TicketFlags , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('authtime', KerberosTime , {'tag_type': TAG, 'tag': 4, 'optional': True}),
		('starttime', KerberosTime , {'tag_type': TAG, 'tag': 5, 'optional': True}),
		('endtime', KerberosTime , {'tag_type': TAG, 'tag': 6, 'optional': True}),
		('renew-till', KerberosTime , {'tag_type': TAG, 'tag': 7, 'optional': True}),
		('srealm', Realm , {'tag_type': TAG, 'tag': 8, 'optional': True}),
		('sname', PrincipalName , {'tag_type': TAG, 'tag': 9, 'optional': True}),
		('caddr', HostAddresses , {'tag_type': TAG, 'tag': 10, 'optional': True}),
	]
	
class SequenceOfKrbCredInfo(core.SequenceOf):
	_child_spec = KrbCredInfo
	
class EncKrbCredPart(core.Sequence):
	explicit = (APPLICATION, 29)
	_fields = [
		('ticket-info', SequenceOfKrbCredInfo, {'tag_type': TAG, 'tag': 0}),
		('nonce', krb5int32, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('timestamp', KerberosTime , {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('usec', krb5int32 , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('s-address', HostAddress , {'tag_type': TAG, 'tag': 4, 'optional': True}),
		('r-address', HostAddress , {'tag_type': TAG, 'tag': 5, 'optional': True}),
	]

class KRB_ERROR(core.Sequence):
	explicit = (APPLICATION, 30)
	_fields = [
		('pvno', krb5int32, {'tag_type': TAG, 'tag': 0}),
		('msg-type',krb5int32 , {'tag_type': TAG, 'tag': 1}), #MESSAGE_TYPE
		('ctime', KerberosTime , {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('cusec', krb5int32 , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('stime', KerberosTime , {'tag_type': TAG, 'tag': 4}),
		('susec', krb5int32 , {'tag_type': TAG, 'tag': 5}),
		('error-code', krb5int32 , {'tag_type': TAG, 'tag': 6}),
		('crealm', Realm , {'tag_type': TAG, 'tag': 7, 'optional': True}),
		('cname', PrincipalName , {'tag_type': TAG, 'tag': 8, 'optional': True}),
		('realm', Realm , {'tag_type': TAG, 'tag': 9}),
		('sname', PrincipalName , {'tag_type': TAG, 'tag': 10}),
		('e-text', core.GeneralString , {'tag_type': TAG, 'tag': 11, 'optional': True}),
		('e-data', core.OctetString , {'tag_type': TAG, 'tag': 12, 'optional': True}),
	]

class ChangePasswdDataMS(core.Sequence):
	_fields = [
		('newpasswd', core.OctetString, {'tag_type': TAG, 'tag': 0}),
		('targname', PrincipalName, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('targrealm', Realm , {'tag_type': TAG, 'tag': 2, 'optional': True}),
	]

class EtypeList(core.SequenceOf):
	#-- the client's proposed enctype list in
	#-- decreasing preference order, favorite choice first
	_child_spec = ENCTYPE

	
class KerberosResponse(core.Choice):
	_alternatives = [
		('AS_REP', AS_REP, {'implicit': (APPLICATION,11) }  ),
		('TGS_REP', TGS_REP, {'implicit': (APPLICATION,13) }  ),
		('KRB_ERROR', KRB_ERROR, {'implicit': (APPLICATION,30) } ),
	]
	
	
class KRBCRED(core.Sequence):
	explicit = (APPLICATION, 22)
	
	_fields = [
		('pvno', core.Integer, {'tag_type': TAG, 'tag': 0}),
		('msg-type', core.Integer, {'tag_type': TAG, 'tag': 1}),
		('tickets', SequenceOfTicket, {'tag_type': TAG, 'tag': 2}),
		('enc-part', EncryptedData , {'tag_type': TAG, 'tag': 3}),
	
	]

class KerberosParser:
	def __init__(self):
		pass
	
	@staticmethod
	async def from_streamreader(reader):
		lb = await read_or_exc(reader, 4)
		length = int.from_bytes(lb, byteorder = 'big', signed = False)
		data = await read_or_exc(reader, length)
		
		krb_message = AS_REQ.load(data)
		
		return krb_message