import io
import os
import enum
import base64
import hashlib
import hmac
import collections
from responder3.utils import timestamp2datetime

#https://msdn.microsoft.com/en-us/library/cc236650.aspx
class NegotiateFlags(enum.IntFlag):
	NEGOTIATE_56   = 0x80000000
	NEGOTIATE_KEY_EXCH   = 0x40000000
	NEGOTIATE_128   = 0x20000000
	r1  = 0x10000000
	r2  = 0x8000000
	r3  = 0x4000000
	NEGOTIATE_VERSION   = 0x2000000
	r4  = 0x1000000
	NEGOTIATE_TARGET_INFO   = 0x800000
	REQUEST_NON_NT_SESSION_KEY   = 0x400000
	r5  = 0x200000
	NEGOTIATE_IDENTIFY   = 0x100000
	NEGOTIATE_EXTENDED_SESSIONSECURITY   = 0x80000
	r6  = 0x40000
	TARGET_TYPE_SERVER   = 0x20000
	TARGET_TYPE_DOMAIN   = 0x10000
	NEGOTIATE_ALWAYS_SIGN   = 0x8000
	r7  = 0x4000
	NEGOTIATE_OEM_WORKSTATION_SUPPLIED   = 0x2000
	NEGOTIATE_OEM_DOMAIN_SUPPLIED   = 0x1000
	J   = 0x800
	r8  = 0x400
	NEGOTIATE_NTLM   = 0x200
	r9  = 0x100
	NEGOTIATE_LM_KEY   = 0x80
	NEGOTIATE_DATAGRAM   = 0x40
	NEGOTIATE_SEAL   = 0x20
	NEGOTIATE_SIGN   = 0x10
	r10 = 0x8
	REQUEST_TARGET   = 0x4
	NTLM_NEGOTIATE_OEM   = 0x2
	NEGOTIATE_UNICODE   = 0x1
		
NegotiateFlagExp = {
	NegotiateFlags.NEGOTIATE_56   : 'requests 56-bit encryption. If the client sends NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN with NTLMSSP_NEGOTIATE_56 to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_56 to the client in the CHALLENGE_MESSAGE.   Otherwise it is ignored. If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are requested and supported by the client and server, NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set NTLMSSP_NEGOTIATE_56 if it is supported. An alternate name for this field is NTLMSSP_NEGOTIATE_56.',
	NegotiateFlags.NEGOTIATE_KEY_EXCH   : 'requests an explicit key exchange. This capability SHOULD be used because it improves security for message integrity or confidentiality. See sections 3.2.5.1.2, 3.2.5.2.1, and 3.2.5.2.2 for details. An alternate name for this field is NTLMSSP_NEGOTIATE_KEY_EXCH.',
	NegotiateFlags.NEGOTIATE_128  : 'requests 128-bit session key negotiation. An alternate name for this field is NTLMSSP_NEGOTIATE_128. If the client sends NTLMSSP_NEGOTIATE_128 to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_128 to the client in the CHALLENGE_MESSAGE only if the client sets NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN. Otherwise it is ignored. If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are requested and supported by the client and server, NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set NTLMSSP_NEGOTIATE_128 if it is supported. An alternate name for this field is NTLMSSP_NEGOTIATE_128.<23>',
	NegotiateFlags.r1  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.r2  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.r3  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_VERSION   : 'requests the protocol version number. The data corresponding to this flag is provided in the Version field of the NEGOTIATE_MESSAGE, the CHALLENGE_MESSAGE, and the AUTHENTICATE_MESSAGE.<24> An alternate name for this field is NTLMSSP_NEGOTIATE_VERSION.',
	NegotiateFlags.r4  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_TARGET_INFO   : 'indicates that the TargetInfo fields in the CHALLENGE_MESSAGE (section 2.2.1.2) are populated. An alternate name for this field is NTLMSSP_NEGOTIATE_TARGET_INFO.',
	NegotiateFlags.REQUEST_NON_NT_SESSION_KEY   : ' requests the usage of the LMOWF. An alternate name for this field is NTLMSSP_REQUEST_NON_NT_SESSION_KEY.',
	NegotiateFlags.r5  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_IDENTIFY   : 'requests an identify level token. An alternate name for this field is NTLMSSP_NEGOTIATE_IDENTIFY.',
	NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY  : 'requests usage of the NTLM v2 session security. NTLM v2 session security is a misnomer because it is not NTLM v2. It is NTLM v1 using the extended session security that is also in NTLM v2. NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and NTLMSSP_NEGOTIATE_LM_KEY are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client. NTLM v2 authentication session key generation MUST be supported by both the client and the DC in order to be used, and extended  session security signing and sealing requires support from the client and the server in order to be used.<25> An alternate name for this field is NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.',
	NegotiateFlags.r6  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.TARGET_TYPE_SERVER   : 'TargetName MUST be a server name. The data corresponding to this flag is provided by the server in the TargetName field of the CHALLENGE_MESSAGE. If this bit is set, then NTLMSSP_TARGET_TYPE_DOMAIN MUST NOT be set. This flag MUST be ignored in the NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE. An alternate name for this field is NTLMSSP_TARGET_TYPE_SERVER.',
	NegotiateFlags.TARGET_TYPE_DOMAIN   : 'TargetName MUST be a domain name. The data corresponding to this flag is provided by the server in the TargetName field of the CHALLENGE_MESSAGE. then NTLMSSP_TARGET_TYPE_SERVER MUST NOT be set. This flag MUST be ignored in the NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE. An alternate name for this field is NTLMSSP_TARGET_TYPE_DOMAIN.',
	NegotiateFlags.NEGOTIATE_ALWAYS_SIGN   : ' requests the presence of a signature block on all messages. NTLMSSP_NEGOTIATE_ALWAYS_SIGN MUST be set in the NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. NTLMSSP_NEGOTIATE_ALWAYS_SIGN is overridden by NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL, if they are supported. An alternate name for this field is NTLMSSP_NEGOTIATE_ALWAYS_SIGN.',
	NegotiateFlags.r7  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_OEM_WORKSTATION_SUPPLIED   : 'This flag indicates whether the Workstation field is present. If this flag is not set, the Workstation field MUST be ignored. If this flag is set, the length of the Workstation field specifies whether the workstation name is nonempty or not.<26> An alternate name for this field is NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.',
	NegotiateFlags.NEGOTIATE_OEM_DOMAIN_SUPPLIED   : 'the domain name is provided (section 2.2.1.1).<27> An alternate name for this field is NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.',
	NegotiateFlags.J   : 'the connection SHOULD be anonymous.<28>',
	NegotiateFlags.r8  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_NTLM   : 'requests usage of the NTLM v1 session security protocol. NTLMSSP_NEGOTIATE_NTLM MUST be set in the NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An alternate name for this field is NTLMSSP_NEGOTIATE_NTLM.',
	NegotiateFlags.r9  : 'This bit is unused and MUST be zero.',
	NegotiateFlags.NEGOTIATE_LM_KEY   : 'requests LAN Manager (LM) session key computation. NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client. NTLM v2 authentication session key generation MUST be supported by both the client and the DC in order to be used, and extended session security signing and sealing requires support from the client and the server to be used. An alternate name for this field is NTLMSSP_NEGOTIATE_LM_KEY.',
	NegotiateFlags.NEGOTIATE_DATAGRAM   : 'requests connectionless authentication. If NTLMSSP_NEGOTIATE_DATAGRAM is set, then NTLMSSP_NEGOTIATE_KEY_EXCH MUST always be set in the AUTHENTICATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An alternate name for this field is NTLMSSP_NEGOTIATE_DATAGRAM',
	NegotiateFlags.NEGOTIATE_SEAL   : 'requests session key negotiation for message confidentiality. If the client sends NTLMSSP_NEGOTIATE_SEAL to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_SEAL to the client in the CHALLENGE_MESSAGE. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD always set NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128, if they are supported. An alternate name for this field is NTLMSSP_NEGOTIATE_SEAL.',
	NegotiateFlags.NEGOTIATE_SIGN   : 'requests session key negotiation for message signatures. If the client sends NTLMSSP_NEGOTIATE_SIGN to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_SIGN to the client in the CHALLENGE_MESSAGE. An alternate name for this field is NTLMSSP_NEGOTIATE_SIGN.',
	NegotiateFlags.r10 : 'This bit is unused and MUST be zero.',
	NegotiateFlags.REQUEST_TARGET   : 'TargetName field of the CHALLENGE_MESSAGE (section 2.2.1.2) MUST be supplied. An alternate name for this field is NTLMSSP_REQUEST_TARGET.',
	NegotiateFlags.NTLM_NEGOTIATE_OEM   : 'requests OEM character set encoding. An alternate name for this field is NTLM_NEGOTIATE_OEM. See bit A for details.',
	NegotiateFlags.NEGOTIATE_UNICODE   : 'requests Unicode character set encoding. An alternate name for this field is NTLMSSP_NEGOTIATE_UNICODE.',

}


class Fields():
	def __init__(self, length, offset, maxLength = None):
		self.length = length
		self.maxLength = length if maxLength is None else maxLength
		self.offset = offset

	def from_bytes(bbuff):
		return Fields.from_buffer(io.BytesIO(bbuff))

	def from_buffer( buff):
		length    = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		maxLength = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		offset    = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)

		return Fields(length, offset, maxLength = maxLength)

	def toBytes(self):
		return  self.length.to_bytes(2, byteorder = 'little', signed = False) + \
				self.maxLength.to_bytes(2, byteorder = 'little', signed = False) + \
				self.offset.to_bytes(4, byteorder = 'little', signed = False)

class NTLMAuthenticate():
	def __init__(self):
		self.Signature = None
		self.MessageType = None
		self.LmChallengeResponseFields = None
		self.NtChallengeResponseFields = None
		self.DomainNameFields = None
		self.UserNameFields = None
		self.WorkstationFields = None
		self.EncryptedRandomSessionKeyFields = None
		self.NegotiateFlags = None
		self.Version = None
		self.MIC = None
		self.Payload = None

		#high level
		self.LMChallenge = None
		self.NTChallenge = None
		self.DomainName = None
		self.UserName = None
		self.Workstation = None
		self.EncryptedRandomSession = None

		#for "checking" the password
		self.NTBytes = None
		self.LMBytes = None


	def from_bytes(bbuff):
		return NTLMAuthenticate.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		auth = NTLMAuthenticate()
		auth.Signature    = buff.read(8).decode('ascii')
		auth.MessageType  = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		auth.LmChallengeResponseFields = Fields.from_buffer(buff)
		auth.NtChallengeResponseFields = Fields.from_buffer(buff)
		auth.DomainNameFields = Fields.from_buffer(buff)
		auth.UserNameFields = Fields.from_buffer(buff)
		auth.WorkstationFields = Fields.from_buffer(buff)
		auth.EncryptedRandomSessionKeyFields = Fields.from_buffer(buff)
		auth.NegotiateFlags = NegotiateFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		if auth.NegotiateFlags & NegotiateFlags.NEGOTIATE_VERSION: 
			auth.Version = Version.from_buffer(buff)

		## TODO: I'm not sure about this condition!!! Need to test this!
		if auth.NegotiateFlags & NegotiateFlags.NEGOTIATE_ALWAYS_SIGN:
			auth.MIC = int.from_bytes(buff.read(16), byteorder = 'little', signed = False)
		#auth.Payload = buff.read()

		##### MASSIVE BIG TODO!!!
		####here we shoudl decide which version of NTLM is used!!!!
		####Now I'm assuming ntlmv2
		####DID YOU JUST ASSUME MY AUTHENTICATION PROTOCOL VERSION???

		currPos = buff.tell()

		buff.seek(auth.LmChallengeResponseFields.offset,io.SEEK_SET)
		auth.LMBytes = buff.read(auth.LmChallengeResponseFields.length)
		buff.seek(auth.LmChallengeResponseFields.offset,io.SEEK_SET)
		auth.LMChallenge = LMv2Response.from_buffer(buff)
		
		buff.seek(auth.NtChallengeResponseFields.offset,io.SEEK_SET)
		auth.NTBytes = buff.read(auth.NtChallengeResponseFields.length)
		buff.seek(auth.NtChallengeResponseFields.offset,io.SEEK_SET)
		auth.NTChallenge = NTLMv2Response.from_buffer(buff)
		
		buff.seek(auth.DomainNameFields.offset,io.SEEK_SET)
		auth.DomainName = buff.read(auth.DomainNameFields.length).decode('utf-16le')
		
		buff.seek(auth.UserNameFields.offset,io.SEEK_SET)
		auth.UserName = buff.read(auth.UserNameFields.length).decode('utf-16le')

		buff.seek(auth.WorkstationFields.offset,io.SEEK_SET)
		auth.Workstation = buff.read(auth.WorkstationFields.length).decode('utf-16le')

		buff.seek(auth.EncryptedRandomSessionKeyFields.offset,io.SEEK_SET)
		auth.EncryptedRandomSession = buff.read(auth.EncryptedRandomSessionKeyFields.length).decode('utf-16le')
		
		buff.seek(currPos, io.SEEK_SET)

		return auth

	def __repr__(self):
		t  = '== NTLMAuthenticate ==\r\n'
		t += 'Signature     : %s\r\n' % repr(self.Signature)
		t += 'MessageType   : %s\r\n' % repr(self.MessageType)
		t += 'NegotiateFlags: %s\r\n' % repr(self.NegotiateFlags)
		t += 'Version       : %s\r\n' % repr(self.Version)
		t += 'MIC           : %s\r\n' % repr(self.MIC)
		t += 'LMChallenge   : %s\r\n' % repr(self.LMChallenge)
		t += 'NTChallenge   : %s\r\n' % repr(self.NTChallenge)
		t += 'DomainName    : %s\r\n' % repr(self.DomainName)
		t += 'UserName      : %s\r\n' % repr(self.UserName)
		t += 'Workstation   : %s\r\n' % repr(self.Workstation)
		t += 'EncryptedRandomSession: %s\r\n' % repr(self.EncryptedRandomSession)
		return t


#https://msdn.microsoft.com/en-us/library/cc236648.aspx
class LMResponse():
	def __init__(self):
		self.Response = None

	def from_bytes(bbuff):
		return LMResponse.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		t = LMResponse()
		t.Response = buff.read(24).hex()
		return t

	def __repr__(self):
		t  = '== LMResponse ==\r\n'
		t += 'Response: %s\r\n' % repr(self.Response)
		return t

#https://msdn.microsoft.com/en-us/library/cc236649.aspx
class LMv2Response():
	def __init__(self):
		self.Response = None
		self.ChallengeFromClinet = None

	def from_bytes(bbuff):
		return LMv2Response.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		t = LMv2Response()
		t.Response = buff.read(16).hex()
		t.ChallengeFromClinet = buff.read(8).hex()
		return t

	def __repr__(self):
		t  = '== LMv2Response ==\r\n'
		t += 'Response: %s\r\n' % repr(self.Response)
		t += 'ChallengeFromClinet: %s\r\n' % repr(self.ChallengeFromClinet)
		return t

#https://msdn.microsoft.com/en-us/library/cc236651.aspx
class NTLMv1Response():
	def __init__(self):
		self.Response = None

	def from_bytes(bbuff):
		return NTLMv1Response.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		t = NTLMv1Response()
		t.Response = buff.read(24).hex()
		return t

	def __repr__(self):
		t  = '== NTLMv1Response ==\r\n'
		t += 'Response: %s\r\n' % repr(self.Response)
		return t

#https://msdn.microsoft.com/en-us/library/cc236653.aspx
class NTLMv2Response():
	def __init__(self):
		self.Response = None
		self.ChallengeFromClinet = None

	def from_bytes(bbuff):
		return NTLMv2Response.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		t = NTLMv2Response()
		t.Response = buff.read(16).hex()
		t.ChallengeFromClinet = NTLMv2ClientChallenge.from_buffer(buff)
		return t

	def __repr__(self):
		t  = '== NTLMv2Response ==\r\n'
		t += 'Response           : %s\r\n' % repr(self.Response)
		t += 'ChallengeFromClinet: %s\r\n' % repr(self.ChallengeFromClinet)
		return t



class NTLMv2ClientChallenge():
	def __init__(self):
		self.RespType   = None
		self.HiRespType = None
		self.Reserved1  = None
		self.Reserved2  = None
		self.TimeStamp  = None
		self.ChallengeFromClient = None
		self.Reserved3  = None
		self.Reserved3  = None
		self.Details    = None #named AVPairs in the documentation

	def from_bytes(bbuff):
		return NTLMv2ClientChallenge.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		cc = NTLMv2ClientChallenge()
		cc.RespType   = int.from_bytes(buff.read(1), byteorder = 'little', signed = False)
		cc.HiRespType = int.from_bytes(buff.read(1), byteorder = 'little', signed = False)
		cc.Reserved1  = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		cc.Reserved2  = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		cc.TimeStamp  = timestamp2datetime(buff.read(8))
		cc.ChallengeFromClient = buff.read(8).hex()
		cc.Reserved3  = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		cc.Details    = AVPairs.from_buffer(buff)

		return cc

	def __repr__(self):
		t  = '== NTLMv2ClientChallenge ==\r\n'
		t += 'RespType           : %s\r\n' % repr(self.RespType)
		t += 'TimeStamp          : %s\r\n' % repr(self.TimeStamp)
		t += 'ChallengeFromClient: %s\r\n' % repr(self.ChallengeFromClient)
		t += 'Details            : %s\r\n' % repr(self.Details)
		return t


class NTLMChallenge():
	def __init__(self):
		self.Signature         = 'NTLMSSP\x00'
		self.MessageType       = 2
		self.TargetNameFields  = None
		self.NegotiateFlags    = None
		self.ServerChallenge   = None
		self.Reserved          = (b'\x00'*8).hex()
		self.TargetInfoFields  = None
		self.Version           = None
		self.Payload           = None

		self.TargetName        = None
		self.TargetInfo        = None


	
	def construct_from_template(templateName = 'Windows2003'):
		version    = NTLMTemplates[templateName]['version']
		challenge  = NTLMTemplates[templateName]['challenge'] if NTLMTemplates[templateName]['challenge'] is not None else os.urandom(8).hex()
		targetName = NTLMTemplates[templateName]['targetname']
		targetInfo = NTLMTemplates[templateName]['targetinfo']
		targetInfo = NTLMTemplates[templateName]['targetinfo']
		flags      = NTLMTemplates[templateName]['flags']

		return NTLMChallenge.construct(challenge=challenge, targetName = targetName, targetInfo = targetInfo, version = version, flags= flags)
	
	
	##TODO: needs some clearning up (like re-calculating flags when needed)
	def construct(challenge = os.urandom(8), targetName = None, targetInfo = None, version = None, flags = None):
		t = NTLMChallenge()
		t.NegotiateFlags    = flags
		t.Version           = version
		t.ServerChallenge   = challenge
		t.TargetName        = targetName
		t.TargetInfo        = targetInfo

		t.TargetNameFields = Fields(len(t.TargetName.encode('utf-16le')),56) 
		t.TargetInfoFields = Fields(len(t.TargetInfo.toBytes()), 56 + len(t.TargetName.encode('utf-16le')))

		t.Payload = t.TargetName.encode('utf-16le')
		t.Payload += t.TargetInfo.toBytes()

		return t


	def toBytes(self):
		tn = self.TargetName.encode('utf-16le')
		ti = self.TargetInfo.toBytes()

		buff  = self.Signature.encode('ascii')
		buff += self.MessageType.to_bytes(4, byteorder = 'little', signed = False)
		buff += self.TargetNameFields.toBytes()
		buff += self.NegotiateFlags.to_bytes(4, byteorder = 'little', signed = False)
		buff += bytes.fromhex(self.ServerChallenge)
		buff += bytes.fromhex(self.Reserved)
		buff += self.TargetInfoFields.toBytes()
		buff += self.Version.toBytes()
		buff += self.Payload
		

		return buff

	def __repr__(self):
		t  = '== NTLMChallenge ==\r\n'
		t += 'Signature      : %s\r\n' % repr(self.Signature)
		t += 'MessageType    : %s\r\n' % repr(self.TimeStamp)
		t += 'ServerChallenge: %s\r\n' % repr(self.ServerChallenge)
		t += 'TargetName     : %s\r\n' % repr(self.TargetName)
		t += 'TargetInfo     : %s\r\n' % repr(self.TargetInfo)
		return t

	def toBase64(self):
		return base64.b64encode(self.toBytes()).decode('ascii')

#???? https://msdn.microsoft.com/en-us/library/windows/desktop/aa374793(v=vs.85).aspx
#https://msdn.microsoft.com/en-us/library/cc236646.aspx
class AVPairs(collections.UserDict):
	"""
	AVPairs is a dictionary-like object that stores the "AVPair list" in a kev-value format where key is an AVPAIRType object and value is the corresponding object defined by the MSDN documentation. Usually it's string but can be other object as well
	"""
	def __init__(self, data = None):
		collections.UserDict.__init__(self, data)

	def from_bytes(bbuff):
		return AVPairs.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		avp = AVPairs()
		while True:
			avId  = AVPAIRType(int.from_bytes(buff.read(2), byteorder = 'little', signed = False))
			AvLen = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
			if avId == AVPAIRType.MsvAvEOL:
				break

			elif avId in [AVPAIRType.MsvAvNbComputerName,
						  AVPAIRType.MsvAvNbDomainName,
						  AVPAIRType.MsvAvDnsComputerName,
						  AVPAIRType.MsvAvDnsDomainName,
						  AVPAIRType.MsvAvDnsTreeName,
						  AVPAIRType.MsvAvTargetName,
			]:
				avp[avId] = buff.read(AvLen).decode('utf-16le')

			### TODO IMPLEMENT PARSING OFR OTHER TYPES!!!!
			else:
				avp[avId] = buff.read(AvLen)

		return avp

	def toBytes(self):
		t = b''
		for av in self.data:
			t += AVPair(data = self.data[av], type = av).toBytes()

		t+= AVPair(data = '', type = AVPAIRType.MsvAvEOL).toBytes()
		return t

class AVPair():
	def __init__(self, data = None, type = None):
		self.type = type
		self.data = data

	def toBytes(self):
		t  = self.type.value.to_bytes(2, byteorder = 'little', signed = False)
		t += len(self.data.encode('utf-16le')).to_bytes(2, byteorder = 'little', signed = False)
		t += self.data.encode('utf-16le')
		return t


class AVPAIRType(enum.Enum):
	MsvAvEOL             = 0x0000 #Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
	MsvAvNbComputerName  = 0x0001 #The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
	MsvAvNbDomainName    = 0x0002 #The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
	MsvAvDnsComputerName = 0x0003 #The fully qualified domain name (FQDN) of the computer. The name MUST be in Unicode, and is not null-terminated.
	MsvAvDnsDomainName   = 0x0004 #The FQDN of the domain. The name MUST be in Unicode, and is not null-terminated.
	MsvAvDnsTreeName     = 0x0005 #The FQDN of the forest. The name MUST be in Unicode, and is not null-terminated.<13>
	MsvAvFlags           = 0x0006 #A 32-bit value indicating server or client configuration.
	MsvAvTimestamp       = 0x0007 #A FILETIME structure ([MS-DTYP] section 2.3.3) in little-endian byte order that contains the server local time. This structure is always sent in the CHALLENGE_MESSAGE.<16>
	MsvAvSingleHost      = 0x0008 #A Single_Host_Data (section 2.2.2.2) structure. The Value field contains a platform-specific blob, as well as a MachineID created at computer startup to identify the calling machine.<17>
	MsvAvTargetName      = 0x0009 #The SPN of the target server. The name MUST be in Unicode and is not null-terminated.<18>
	MsvChannelBindings   = 0x000A #A channel bindings hash. The Value field contains an MD5 hash ([RFC4121] section 4.1.1.2) of a gss_channel_bindings_struct ([RFC2744] section 3.11). An all-zero value of the hash is used to indicate absence of channel bindings.<19>


#https://msdn.microsoft.com/en-us/library/cc236641.aspx
class NTLMNegotiate():
	def __init__(self):
		self.Signature         = None
		self.MessageType       = None
		self.NegotiateFlags    = None
		self.DomainNameFields  = None
		self.WorkstationFields = None
		self.Version           = None
		self.Payload           = None

		####High-level variables
		self.Domain      = None
		self.Workstation = None

	def from_bytes(bbuff):
		return NTLMNegotiate.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		t = NTLMNegotiate()
		t.Signature         = buff.read(8).decode('ascii')
		t.MessageType       = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		t.NegotiateFlags    = NegotiateFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		t.DomainNameFields  = Fields.from_buff(buff)
		t.WorkstationFields = Fields.from_buff(buff)

		if t.NegotiateFlags & NegotiateFlags.NEGOTIATE_VERSION: 
			t.Version = buff.read(8)

		currPos = buff.tell()
		
		if t.DomainNameFields.length != 0:
			buff.seek(t.DomainNameFields.offset,io.SEEK_SET)
			self.Domain = buff.read(t.DomainNameFields.length).decode('utf-16le')
		if t.WorkstationFields.length != 0:
			buff.seek(t.WorkstationFields.offset,io.SEEK_SET)
			self.Workstation = buff.read(t.WorkstationFields.length).decode('utf-16le')
		
		buff.seek(currPos, io.SEEK_SET)
		return t

	def __repr__(self):
		t  = '== NTLMNegotiate ==\r\n'
		t += 'Signature  : %s\r\n' % repr(self.Signature)
		t += 'MessageType: %s\r\n' % repr(self.TimeStamp)
		t += 'Version    : %s\r\n' % repr(self.Version)
		t += 'Domain     : %s\r\n' % repr(self.Domain)
		t += 'Workstation: %s\r\n' % repr(self.Workstation)
		return t

	def contrct(self):
		pass

class Version():
	def __init__(self):
		self.ProductMajorVersion = None
		self.ProductMinorVersion = None
		self.ProductBuild        = None
		self.Reserved            = None
		self.NTLMRevisionCurrent = None

		#higher level
		self.WindowsProduct = None

	def toBytes(self):
		t = self.ProductMajorVersion.value.to_bytes(1, byteorder = 'little', signed = False)
		t += self.ProductMinorVersion.value.to_bytes(1, byteorder = 'little', signed = False)
		t += self.ProductBuild.to_bytes(2, byteorder = 'little', signed = False)
		t += self.Reserved.to_bytes(3, byteorder = 'little', signed = False)
		t += self.NTLMRevisionCurrent.value.to_bytes(1, byteorder = 'little', signed = False)
		return t

	def from_bytes(bbuff):
		return Version.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		v = Version()
		v.ProductMajorVersion = WindowsMajorVersion(int.from_bytes(buff.read(1), byteorder = 'little', signed = False))
		v.ProductMinorVersion = WindowsMinorVersion(int.from_bytes(buff.read(1), byteorder = 'little', signed = False))
		v.ProductBuild        = int.from_bytes(buff.read(2), byteorder = 'little', signed = False)
		v.Reserved            = int.from_bytes(buff.read(3), byteorder = 'little', signed = False)
		v.NTLMRevisionCurrent = NTLMRevisionCurrent(int.from_bytes(buff.read(1), byteorder = 'little', signed = False))

		v.WindowsProduct = WindowsProduct[(v.ProductMajorVersion, v.ProductMinorVersion)]

		return v

	def __repr__(self):
		t  = '== NTLMVersion ==\r\n'
		t += 'ProductMajorVersion  : %s\r\n' % repr(self.ProductMajorVersion.name)
		t += 'ProductMinorVersion  : %s\r\n' % repr(self.ProductMinorVersion.name)
		t += 'ProductBuild         : %s\r\n' % repr(self.ProductBuild)
		t += 'WindowsProduct       : %s\r\n' % repr(self.WindowsProduct)
		return t


class NTLMRevisionCurrent(enum.Enum):
	NTLMSSP_REVISION_W2K3 = 0x0F

#https://msdn.microsoft.com/en-us/library/cc236722.aspx#Appendix_A_33
class WindowsMajorVersion(enum.Enum):
	WINDOWS_MAJOR_VERSION_5  = 0x05
	WINDOWS_MAJOR_VERSION_6  = 0x06
	WINDOWS_MAJOR_VERSION_10 = 0x0A
#https://msdn.microsoft.com/en-us/library/cc236722.aspx#Appendix_A_33
class WindowsMinorVersion(enum.Enum):
	WINDOWS_MINOR_VERSION_0 = 0x00
	WINDOWS_MINOR_VERSION_1 = 0x01
	WINDOWS_MINOR_VERSION_2 = 0x02
	WINDOWS_MINOR_VERSION_3 = 0x03
#https://msdn.microsoft.com/en-us/library/cc236722.aspx#Appendix_A_33

WindowsProduct = {
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_5, WindowsMinorVersion.WINDOWS_MINOR_VERSION_1) : 'Windows XP operating system Service Pack 2 (SP2)',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_5, WindowsMinorVersion.WINDOWS_MINOR_VERSION_2) : 'Windows Server 2003',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_6, WindowsMinorVersion.WINDOWS_MINOR_VERSION_0) : 'Windows Vista or Windows Server 2008',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_6, WindowsMinorVersion.WINDOWS_MINOR_VERSION_1) : 'Windows 7 or Windows Server 2008 R2',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_6, WindowsMinorVersion.WINDOWS_MINOR_VERSION_2) : 'Windows 8 or Windows Server 2012 operating system',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_6, WindowsMinorVersion.WINDOWS_MINOR_VERSION_3) : 'Windows 8.1 or Windows Server 2012 R2',
	(WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10,WindowsMinorVersion.WINDOWS_MINOR_VERSION_0) : 'Windows 10 or Windows Server 2016',
}

NTLMTemplates = {
		"Windows2003" : {
							'flags'      :  NegotiateFlags.NEGOTIATE_56|NegotiateFlags.NEGOTIATE_128|
											NegotiateFlags.NEGOTIATE_VERSION|NegotiateFlags.NEGOTIATE_TARGET_INFO|
											NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY|
											NegotiateFlags.TARGET_TYPE_DOMAIN|NegotiateFlags.NEGOTIATE_NTLM|
											NegotiateFlags.REQUEST_TARGET|NegotiateFlags.NEGOTIATE_UNICODE ,
							'version'    : Version.from_bytes(b"\x05\x02\xce\x0e\x00\x00\x00\x0f"),
							'targetinfo' : AVPairs({ AVPAIRType.MsvAvNbDomainName    : 'SMB',
												AVPAIRType.MsvAvNbComputerName       : 'SMB-TOOLKIT',
												AVPAIRType.MsvAvDnsDomainName        : 'smb.local',
												AVPAIRType.MsvAvDnsComputerName      : 'server2003.smb.local',
												AVPAIRType.MsvAvDnsTreeName          : 'smb.local',
									       }),

							'targetname' : 'SMB',
							'challenge'  : 'AAAAAAAAAAAAAAAA', #None = random


						}



	}

##def verifyNTLMv2(user, domain, cchall, schall, NTHash = None, password = None):

def genNTHash(password):
	return hashlib.new('md4', password.encode('utf-16le')).digest()

def genNTLMv2(user, domain, cchall, schall, NTHash = None, password = None):
	if NTHash is None and password is None:
		raise Exception('either password or NThash must be supplied!')
	
	NTHash = bytes.fromHex(NTHash)
	if password is not None:
		NTHash = genNTHash(password)
	
	fp = hmac.new(NTHash, digestmod = hashlib.md5)
	fp.update(user.upper().decode('utf-16le'))
	fp.update(domain.decode('utf-16le'))

	
	hm = hmac.new(fp.digest(), digestmod = hashlib.md5)
	hm.update(bytes.fromHex(schall))
	hm.update(bytes.fromHex(cchall))
	return hm.digest()



"""
if __name__ == '__main__':
	temp = int.from_bytes(b"\x05\x02\x89\xa2", byteorder = 'little', signed = False)
	n = NegotiateFlags(temp)
	print(repr(n))
	
	members, uncovered = enum._decompose(n.__class__, n._value_)
	for k in members:
		print('%s : %s' % (k,NegotiateFlagExp[k]))


"""