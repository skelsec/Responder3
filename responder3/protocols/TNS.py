
# https://blog.pythian.com/repost-oracle-protocol/
# https://github.com/SpiderLabs/net-tns
# http://ckng62.blogspot.com/2014/02/tns-data-packet-structure.html
# http://www.nyoug.org/Presentations/2008/Sep/Harris_Listening%20In.pdf

import enum
import io

from responder3.core.asyncio_helpers import *

class TNSPacketType(enum.Enum):
	UNK_0 = 0
	CONNECT = 1
	ACCEPT = 2
	ACK = 3
	REFUSE = 4
	REDIRECT = 5
	DATA = 6
	NULL = 7
	UNK_8 = 8
	ABORT = 9
	UNK_10 = 10
	RESEND = 11
	MARKER = 12
	ATTENTION = 13
	CONTROL = 14
	UNK_15 = 15

class TNSPacket:
	def __init__(self):
		self.header = None
		self.payload = None

	def to_bytes(self):
		data = self.payload.to_bytes()
		if not self.header:
			self.header = TNSHeader()
			self.header.packet_length = len(data) + 8
			self.header.packet_checksum = 0
			self.header.packet_type = tnstype2class_inv[type(self.payload)]
			self.header.flags = 0
			self.header.checksum = 0		
		
		return self.header.to_bytes() + data

	@staticmethod
	def from_bytes(bbuff):
		return TNSPacket.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		packet = TNSPacket() 
		packet.header = TNSHeader.from_buffer(buff)
		packet.payload = tnstype2class[packet.header.packet_type].from_buffer(buff)
		return packet

	@staticmethod
	async def from_streamreader(reader):
		t_length = await readexactly_or_exc(reader, 2)
		length = int.from_bytes(t_length,byteorder = 'big', signed = False) - 2
		data = await readexactly_or_exc(reader, length)
		return TNSPacket.from_bytes(t_length + data)


class TNSHeader:
	def __init__(self):
		self.packet_length = None
		self.packet_checksum = None
		self.packet_type = None
		self.flags = None
		self.checksum = None

	@staticmethod
	def from_bytes(bbuff):
		return TNSHeader.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		hdr = TNSHeader() 
		hdr.packet_length = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		hdr.packet_checksum = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		hdr.packet_type = TNSPacketType(int.from_bytes(buff.read(1),byteorder = 'big', signed = False))
		hdr.flags = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		hdr.checksum = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		return hdr

	def to_bytes(self):
		t  = self.packet_length.to_bytes(2, byteorder = 'big', signed = False)
		t += self.packet_checksum.to_bytes(2, byteorder = 'big', signed = False)
		t += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.flags.to_bytes(1, byteorder = 'big', signed = False)
		t += self.checksum.to_bytes(2, byteorder = 'big', signed = False)
		return t

class TNSConnect:
	def __init__(self):
		self.maximum_version = None
		self.minimum_version = None
		self.service_flags = None
		self.sdu_size = None
		self.maximum_tdu_size = None
		self.protocol_flags = None
		self.line_turnaround_value = None
		self.byte_order = None
		self.data_length = None
		self.data_offset = None
		self.maximum_connect_receive = None
		self.flags1 = None
		self.flags2 = None
		self.trace_item1 = None
		self.trace_item2 = None
		self.trace_connection_id = None
		self.unknown = None
		self.data = None

	@staticmethod
	def from_bytes(bbuff):
		return TNSConnect.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		tns = TNSConnect() 
		tns.maximum_version = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.minimum_version = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.service_flags = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.sdu_size = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.maximum_tdu_size = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.protocol_flags = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.line_turnaround_value = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.byte_order = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.data_length = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.data_offset = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.maximum_connect_receive = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.flags1 = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		tns.flags2 = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		tns.trace_item1 = int.from_bytes(buff.read(4),byteorder = 'big', signed = False)
		tns.trace_item2 = int.from_bytes(buff.read(4),byteorder = 'big', signed = False)
		tns.trace_connection_id = int.from_bytes(buff.read(8),byteorder = 'big', signed = False)
		tns.unknown = int.from_bytes(buff.read(8),byteorder = 'big', signed = False)
		tns.data = buff.read(-1).decode()
		return tns

class TNSAccept:
	def __init__(self):
		self.version = None
		self.service_flags = None
		self.sdu_size = None
		self.maximum_tdu_size = None
		self.byte_order = None
		self.data_length = None
		self.data_offset = None
		self.flags1 = None
		self.flags2 = None
		self.padding = None
		self.data = None

	@staticmethod
	def from_bytes(bbuff):
		return TNSAccept.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		tns = TNSAccept()
		tns.version = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.service_flags = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.sdu_size = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.maximum_tdu_size = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.byte_order = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.data_length = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.data_offset = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.flags1 = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		tns.flags2 = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		tns.padding = buff.read(tns.data_offset - 24)
		tns.data = buff.read(tns.data_length)

		return tns

	def to_bytes(self):
		t = self.version.to_bytes(2, byteorder = 'big', signed = False)
		t += self.service_flags.to_bytes(2, byteorder = 'big', signed = False)
		t += self.sdu_size.to_bytes(2, byteorder = 'big', signed = False)
		t += self.maximum_tdu_size.to_bytes(2, byteorder = 'big', signed = False)
		t += self.byte_order.to_bytes(2, byteorder = 'big', signed = False)
		self.data_length = len(self.data) if self.data else 0
		t += self.data_length.to_bytes(2, byteorder = 'big', signed = False)
		t += self.data_offset.to_bytes(2, byteorder = 'big', signed = False)
		t += self.flags1.to_bytes(1, byteorder = 'big', signed = False)
		t += self.flags2.to_bytes(1, byteorder = 'big', signed = False)
		if self.padding:
			t += self.padding
		if self.data:
			t += self.data
		return t

class TNSRefuse:
	def __init__(self):
		self.user_reason = None
		self.system_reason = None
		self.data_length = None
		self.data = None

	@staticmethod
	def from_bytes(bbuff):
		return TNSRefuse.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		tns = TNSRefuse()
		tns.user_reason = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		tns.system_reason = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		tns.data_length = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.data = buff.read(tns.data_length)
		
		return tns

class TNSRedirect:
	def __init__(self):
		self.data_length = None
		self.data = None

	@staticmethod
	def from_bytes(bbuff):
		return TNSRedirect.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		tns = TNSRedirect()
		tns.data_length = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.data = buff.read(tns.data_length)
		return tns

class TNSResend:
	def __init__(self):
		pass

	def to_bytes(self):
		return b''

class TNSNull:
	def __init__(self):
		pass

class TNSAck:
	def __init__(self):
		pass

class TNSAttention:
	def __init__(self):
		pass

class TNSControl:
	def __init__(self):
		pass

class TNSAbort:
	def __init__(self):
		self.user_reason = None
		self.system_reason = None
		self.data = None

	@staticmethod
	def from_bytes(bbuff):
		return TNSAbort.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		tns = TNSAbort()
		tns.user_reason = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		tns.system_reason = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		tns.data = buff.read(-1)
		return tns

class TNSData:
	def __init__(self):
		self.flags = None
		self.data = None

	@staticmethod
	def from_bytes(bbuff):
		return TNSData.from_buffer(io.BytesIO(bbuff))

	# TODO: more processing of data
	@staticmethod
	def from_buffer(buff):
		tns = TNSData()
		tns.flags = int.from_bytes(buff.read(2),byteorder = 'big', signed = False)
		tns.data = buff.read(-1)

		return tns

	def to_bytes(self):
		t = self.flags.to_bytes(2 ,byteorder = 'big', signed = False)
		t += self.data
		return t

class TNSMarker:
	def __init__(self):
		self.marker_type = None
		self.data = None

	@staticmethod
	def from_bytes(bbuff):
		return TNSMarker.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		tns = TNSMarker()
		tns.marker_type = int.from_bytes(buff.read(1),byteorder = 'big', signed = False)
		tns.data = buff.read(-1)

		return tns

class TNSXXX:
	def __init__(self):
		self.data = None

	@staticmethod
	def from_bytes(bbuff):
		return TNSXXX.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		tns = TNSXXX()
		tns.data = buff.read(-1)
		return tns

tnstype2class = {
	TNSPacketType.UNK_0 : TNSXXX,
	TNSPacketType.CONNECT : TNSConnect,
	TNSPacketType.ACCEPT : TNSAccept,
	TNSPacketType.ACK : TNSAck,
	TNSPacketType.REFUSE : TNSRefuse,
	TNSPacketType.REDIRECT : TNSRedirect,
	TNSPacketType.DATA : TNSData,
	TNSPacketType.NULL : TNSNull,
	TNSPacketType.UNK_8 : TNSXXX,
	TNSPacketType.ABORT : TNSAbort,
	TNSPacketType.UNK_10 : TNSXXX,
	TNSPacketType.RESEND : TNSResend,
	TNSPacketType.MARKER : TNSMarker,
	TNSPacketType.ATTENTION : TNSAttention,
	TNSPacketType.CONTROL : TNSControl,
	TNSPacketType.UNK_15 : TNSXXX,
}

tnstype2class_inv = {v: k for k, v in tnstype2class.items()}