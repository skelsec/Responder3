#https://tools.ietf.org/html/rfc6143

import enum
import io

from responder3.core.commons import *
from responder3.core.asyncio_helpers import *

class VNCSessionStatus:
	PROTOCOL_EXCH = 0
	SECURITY = 1
	AUTHENTICATION = 2
	AUTHORISED = 3
	

class VNCSecurityTypes(enum.Enum):
	INVALID = 0
	NONE = 1
	VNC_AUTHENTICATION = 2
	
class SecurityResultHandshakeStatus(enum.Enum):
	OK = 0
	FAILED = 1

class ProtocolVersion:
	def __init__(self):
		self.protocolversion = None #RFB 003.008\n
		
	def to_bytes(self):
		return self.protocolversion.encode()
		
	@staticmethod
	def from_bytes(data):
		return ProtocolVersion.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		pv = ProtocolVersion()
		pv.protocolversion = buff.read(12).decode()
		return pv
	
	
class SecurityHandshake:
	def __init__(self):
		self.security_types_len = None #1 byte
		self.security_types = None #security_types_len bytes, list of VNCSecurityTypes enum
		
	def to_bytes(self):
		t = len(self.security_types).to_bytes(1, byteorder = 'big', signed = False)
		for st in self.security_types:
			t += st.value.to_bytes(1, byteorder = 'big', signed = False)
		return t
		
class SecurityHandshakeResponse:
	def __init__(self):
		self.security_type = None #1 byte, VNCSecurityTypes
		
	@staticmethod
	def from_bytes(data):
		return SecurityHandshakeResponse.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		t = SecurityHandshakeResponse()
		try:
			t.security_type = VNCSecurityTypes(buff.read(1)[0])
		except Exception as e:
			#reason for this exception: some uber-smart VNC clients have extended the RFC without telling anyone
			t.security_type = None
		return t
		
class SecurityResultHandshake:
	def __init__(self):
		self.status = None #SecurityResultHandshakeStatus
		self.err_reason = 'Not supported!'
		
	def to_bytes(self):
		if self.status == SecurityResultHandshakeStatus.OK:
			return self.status.value.to_bytes(1, byteorder = 'big', signed = False)
		else:
			edata = self.err_reason.encode()
			data = self.status.value.to_bytes(1, byteorder = 'big', signed = False)
			data += len(edata).to_bytes(4, byteorder = 'big', signed = False)
			data += edata
			return data
		
class VNCAuthentication:
	def __init__(self):
		self.challenge = None #16 bytes random
		
	def to_bytes(self):
		return self.challenge
		
class VNCAuthenticationResult:
	def __init__(self):
		self.response = None #16 bytes, encrypted server random with password DES!
		
	@staticmethod
	def from_bytes(data):
		return VNCAuthenticationResult.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		t = VNCAuthenticationResult()
		t.response = buff.read(16)
		return t

class VNCMessageParser:
	def __init__(self, session):
		self.session = session
		
	async def from_streamreader(self, reader, timeout = 1):
		if self.session.status == VNCSessionStatus.PROTOCOL_EXCH:
			data = await readexactly_or_exc(reader, 12)
			return ProtocolVersion.from_bytes(data)	
			
		elif self.session.status == VNCSessionStatus.SECURITY:
			data = await readexactly_or_exc(reader, 1)
			return SecurityHandshakeResponse.from_bytes(data)	
		
		elif self.session.status == VNCSessionStatus.AUTHENTICATION:
			data = await readexactly_or_exc(reader, 16)			
			return VNCAuthenticationResult.from_bytes(data)
			
		
		
		
		
		
		
		
			