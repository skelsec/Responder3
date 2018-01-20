import io
import enum

#from responder3.newpackets.SMB.SMB import SMB2Message
from responder3.newpackets.SMB.SMB2 import SMB2Message
from responder3.newpackets.SMB.SMB  import SMBMessage

class SMBVersion(enum.Enum):
	V1 = 0xFF
	V2 = 0xFE


class SMBCommandParser():
	def from_bytes(bbuff):
		return SMBCommandParser.from_buffer(io.BytesIO(bbuff))
	
	def from_buffer(buff):
		pos = buff.tell()
		version = SMBVersion(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		buff.seek(pos, io.SEEK_SET)

		#check version of SMB
		if version == SMBVersion.V2:
			return SMB2Message.from_buffer(buff)

		elif version == SMBVersion.V1:
			return SMBMessage.from_buffer(buff)
			#self._parse_SMBv1(self._buffer[4:self._buffer_maxsize])
		
		else:
			raise Exception('Not SMB traffic!')
