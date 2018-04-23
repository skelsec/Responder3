#!/usr/bin/env python3.6
# packettest
from responder3.protocols.SMB.SMB2 import SMB2Message
from responder3.protocols.GSSAPI import *
import io
import enum

class NBTType(enum.Enum):
	SESSION_MESSAGE = 0x00

class NetBIOS():
	def __init__(self):
		self.type = None
		self.datalength = None
		self.data = None

	def from_bytes(bbuff):
		return NetBIOS.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		packet = NetBIOS()
		packet.type = NBTType(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		packet.datalength = int.from_bytes(buff.read(3), byteorder = 'big', signed = False)
		packet.data = buff.read(packet.datalength)
		return packet

	def construct(smbData):
		packet = NetBIOS()
		packet.type = NBTType.SESSION_MESSAGE
		packet.datalength = len(smbData)
		packet.data = smbData

	def to_bytes(self):
		t  = self.type.value.to_bytes(1, byteorder = 'big', signed=False)
		t += len(data).to_bytes(3, byteorder = 'big', signed=False)
		t += self.data
		return t


smb2_negotiate_req = bytes.fromhex('000000aefe534d42400001000000000000001f0000000000000000000000000000000000fffe00000000000000000000000000000000000000000000000000000000000024000500010000007f00000005f6df9d3d05e8119c44448a5b6398b27000000002000000020210020003020311030000010026000000000001002000010055eec52e6a3718bff4ad53d7dd7bf12d3e8b48ed9f0958e681cc45f7e61bb8fd00000200060000000000020002000100')

nb = NetBIOS.from_bytes(smb2_negotiate_req)
smb = SMB2Message.from_bytes(nb.data)
print(repr(smb))



smb2_session_setup_req = bytes.fromhex('000000a2fe534d42400001000000000001001f0000000000000000000100000000000000fffe00000000000000000000000000000000000000000000000000000000000019000001010000000000000058004a000000000000000000604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000000000000000000000000a00ab3f0000000f')
nb = NetBIOS.from_bytes(smb2_session_setup_req)
smb = SMB2Message.from_bytes(nb.data)
print(repr(smb))

print(smb.command.Buffer.hex())

GSSAPI.load(smb.command.Buffer)