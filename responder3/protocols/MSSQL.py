#https://msdn.microsoft.com/en-us/library/dd304523.aspx
#https://msdn.microsoft.com/en-us/library/ee209073(v=sql.105).aspx

#This is the implamentation of the TDS protocol
#The TDS protocol does not prescribe a specific underlying transport protocol to use on the Internet or on other networks. TDS only presumes a reliable transport that guarantees in-sequence delivery of data.

#TODO
#the actual implementation is up for the imagination of the reader

import enum
import io

from responder3.core.asyncio_helpers import *

class SessionStatus(enum.Enum):
	START = enum.auto()
	SSL_AUTH = enum.auto()
	LOGIN7_AUTH = enum.auto()
	SSPI_AUTH = enum.auto()
	AUHTENTICATED = enum.auto()
	PREAUTH_SENT = enum.auto()

class Encryption(enum.Enum):
	OFF = 0x00 #Encryption is available but off.
	ON = 0x01 #Encryption is available and on.
	NOT_SUP = 0x02 #Encryption is not available.
	REQ = 0x03 #Encryption is required.

class PacketType(enum.Enum):
	SQL_BATCH = 1
	PRE_TDS7_LOGIN = 2
	RPC = 3
	TABULAR_RESULT = 4
	UNUSED_5 = 5
	ATTENTION_SIGNAL =6
	BULK_LOAD_DATA=7
	FEDERATED_AUTH_TOKEN = 8
	UNUSED_9 = 9
	UNUSED_10 = 10
	UNUSED_11 = 11
	UNUSED_12 = 12
	UNUSED_13 = 13
	TRANSACTION_MANAGER_REQ = 14
	UNUSED_15 = 15
	LOGIN7 = 16
	SSPI = 17
	PRELOGIN = 18

class PacketStatus(enum.IntFlag):
	NORMAL = 0x00
	EOM = 0x01
	IGNORE = 0x02
	RESET_CONN = 0x08
	RESET_CONN_SKIP_TRAN = 0x10

class TDSPacket:
	def __init__(self):
		self.type = None
		self.status = None
		self.length = None
		self.spid = None
		self.packet_id = None
		self.window = None
		self.data = None

	def hdr_from_bytes(bbuff):
		return TDSPacket.hdr_from_buffer(io.BytesIO(bbuff))

	def hdr_from_buffer(buffer):
		p = TDSPacket()
		p.type = PacketType(int.from_bytes(buffer.read(1), byteorder = 'big', signed = False))
		p.status = PacketStatus(int.from_bytes(buffer.read(1), byteorder = 'big', signed = False))
		p.length = int.from_bytes(buffer.read(2), byteorder = 'big', signed = False)
		p.spid = int.from_bytes(buffer.read(2), byteorder = 'big', signed = False)
		p.packet_id = int.from_bytes(buffer.read(1), byteorder = 'big', signed = False)
		p.window = int.from_bytes(buffer.read(1), byteorder = 'big', signed = False)
		return p

	def to_bytes(self):
		data = self.data.to_bytes()
		t  = self.type.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.status.value.to_bytes(1, byteorder = 'big', signed = False)
		t += (len(data)+8).to_bytes(2, byteorder = 'big', signed = False)
		t += self.spid.to_bytes(2, byteorder = 'big', signed = False)
		t += self.packet_id.to_bytes(1, byteorder = 'big', signed = False)
		t += self.window.to_bytes(1, byteorder = 'big', signed = False)
		return t + data

	def data_from_bytes(self, bbuff):
		self.data = TDSData.from_bytes(type2class[self.type],bbuff)

	def data_from_buffer(self, buffer):
		self.data = TDSData.from_buffer(type2class[self.type],bbuff)

	@staticmethod
	async def from_streamreader(reader, timeout=None):
		t_hdr = await readexactly_or_exc(reader, 8, timeout=timeout)
		hdr = TDSPacket.hdr_from_bytes(t_hdr)
		t_data = await readexactly_or_exc(reader, hdr.length - 8, timeout=timeout)
		hdr.data_from_bytes(t_data)
		return hdr

	def __str__(self):
		t = '== TDSPacket ==\r\n'
		t += 'type : %s\r\n' % self.type
		t += 'status : %s\r\n' % self.status
		t += 'length : %s\r\n' % self.length
		t += 'spid : %s\r\n' % self.spid
		t += 'packet_id : %s\r\n' % self.packet_id
		t += 'window : %s\r\n' % self.window
		t += str(self.data)
		return t

class TDSData:
	def __init__(self):
		pass

	def get_tds_fields(buffer):
		pos = buffer.tell()
		buffer.seek(0,0)
		start = buffer.tell()
		buffer.seek(0,2)
		end = buffer.tell()
		buffer_len = end - start
		buffer.seek(pos, 0)
		fields = []
		cur = TDSField()
		while cur.type != 0xff and buffer.tell() < buffer_len:
			cur = TDSField.from_buffer(buffer)
			fields.append(cur)

		return fields

	@staticmethod
	def from_bytes(ptype, bbuff):
		return ptype.from_buffer(ptype, io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(ptype, buffer):
		p = ptype()
		types, inv, field_types = ptype.get_types()
		for field in TDSData.get_tds_fields(buffer):
			if field.type in inv:
				filed_name = inv[field.type]
				field_type = field_types[filed_name]
				if field_type[0] == 'int':
					setattr(p, filed_name, int.from_bytes(field.data, byteorder = field_type[2], signed = field_type[3]))
				elif field_type[0] == 'enum':
					setattr(p, filed_name, field_type[2](int.from_bytes(field.data, byteorder = 'big', signed = False)))
				elif field_type[0] == 'bool':
					setattr(p, filed_name, bool(int.from_bytes(field.data, byteorder = 'big', signed = False)))
				elif field_type[0] == 'byte':
					setattr(p, filed_name, field.data)
				elif field_type[0] == 'str':
					setattr(p, filed_name, field.data.decode())
				else:
					raise Exception('Unknown field type!')

			else:
				if field.type == 0xff:
					continue
				print('Got type %s, but its not defined' % field.type)

		return p

	def to_bytes(self):
		types, inv, field_types = type(self).get_types()
		tfs = []
		for key in types:
			tf = TDSField()
			tf.type = types[key]
			field_type = field_types[key]
			field_data = getattr(self, key)
			if not field_data:
				continue
			if field_type[0] == 'int':
				tf.data = field_data.to_bytes(field_type[1], byteorder = field_type[2], signed = field_type[3])
			elif field_type[0] == 'enum':
				tf.data = field_data.value.to_bytes(field_type[1], byteorder = 'big', signed = False)
			elif field_type[0] == 'bool':
				tf.data = int(field_data).to_bytes(field_type[1], byteorder = 'big', signed = False)
			elif field_type[0] == 'byte':
				tf.data = field_data
			elif field_type[0] == 'str':
				tf.data = field_data.encode() + b'\x00'
			else:
				raise Exception('Unknown field type!')
			tf.length = len(tf.data)
			tf.offset = 0
			tfs.append(tf)
		data_offset = (len(tfs) * 5) +1
		data = b''
		t = b''
		i = 0
		for tf in tfs:
			tf.offset = data_offset + i
			t += tf.to_bytes()
			i += tf.length
			data += tf.data

		return t + b'\xff'+ data

	def __str__(self):
		types, inv, field_type = type(self).get_types()
		t = '=== %s === \r\n' % type(self)
		for key in types:
			t += '%s: %s\r\n' % (key, getattr(self, key))
		return t

# https://msdn.microsoft.com/en-us/library/dd357559.aspx
class PRELOGIN(TDSData):
	def __init__(self):
		TDSData.__init__(self)
		self.version = None
		self.subbuid = None
		self.encryption = None
		self.instvalidity = None
		self.thread_id = None
		self.mars = None
		self.traceid = None
		self.activity_id = None
		self.activity_seq = None
		self.fedauthrequired = None
		self.nonce = None
		self.terminator = None

	@staticmethod
	def get_types():
		t = {
			'version' : 0,
			#'subbuid' : 0,
			'encryption' : 1,
			'instvalidity' : 2,
			'thread_id' : 3,
			'mars' : 4,
			'traceid' : 5,
			#'activity_id' : 0,
			#'activity_seq' : 0,
			'fedauthrequired' : 6,
			'nonce' : 7,
		}
		inv = {v: k for k, v in t.items()}
		filed_types = {
			'version' : ('byte', 6),#('int', 8, 'big', False),
			#'subbuid' : 0,
			'encryption' : ('enum', 1, Encryption),
			'instvalidity' : ('str', -1),
			'thread_id' : ('int', 8, 'big', False),
			'mars' : ('bool', 1),
			'traceid' : ('byte', 40),
			#'activity_id' : 0,
			#'activity_seq' : 0,
			'fedauthrequired' : ('bool', 1),
			'nonce' : ('byte', 32),
		}
		return t, inv, filed_types

class TDSField:
	def __init__(self):
		self.type = None
		self.offset = None
		self.length = None
		self.data = None

	def to_bytes(self):
		t  = self.type.to_bytes(1, byteorder = 'big', signed = False)
		if self.type == 0xff:
			return t
		t += self.offset.to_bytes(2, byteorder = 'big', signed = False)
		t += self.length.to_bytes(2, byteorder = 'big', signed = False)
		return t

	def read_data(self, buffer):
		pos = buffer.tell()
		buffer.seek(self.offset, 0)
		data = buffer.read(self.length)
		buffer.seek(pos, 0)
		return data

	@staticmethod
	def from_bytes(bbuff):
		return TDSField.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buffer):
		tf = TDSField()
		pos_start = buffer.tell()
		tf.type = int.from_bytes(buffer.read(1), byteorder = 'big', signed = False)
		if tf.type == 0xff: #terminator type
			return tf
		tf.offset = int.from_bytes(buffer.read(2), byteorder = 'big', signed = False)
		tf.length = int.from_bytes(buffer.read(2), byteorder = 'big', signed = False)
		tf.data = tf.read_data(buffer)
		return tf

class TDSEndField(TDSField):
	def __init__(self):
		self.type = 0xff


class LOGIN7:
	def __init__(self):
		self.total_length = None
		self.tds_version = None
		self.packet_size = None
		self.clientprogver = None
		self.client_pid = None
		self.connection_id = None
		self.byteorder = None
		self.flags1 = None
		self.flags2 = None
		self.sql_type_flags = None
		self.flags3 = None
		self.timezone = None
		self.collation = None

		self.cliname_off = None
		self.cliname_len = None
		self.username_off = None
		self.username_len = None
		self.password_off = None
		self.password_len = None
		self.appname_off = None
		self.appname_len = None
		self.servername_off = None
		self.servername_len = None
		self.unused_1_off = None
		self.unused_1_len = None
		self.libname_off = None
		self.libname_len = None
		self.locale_off = None
		self.locale_len = None

		self.dbname_off = None
		self.dbname_off = None

		self.cliname = None
		self.username = None
		self.password = None
		self.appname = None
		self.servername = None
		self.unused = None
		self.libname = None
		self.locale = None
		self.dbname = None

	@staticmethod
	def decode_password(enc_password):
		pw = b''
		for c in enc_password:
			temp = c ^ 0xA5
			temp = ((temp << 4)&0xff) | ((temp >> 4) &0xff)
			pw += temp.to_bytes(1, byteorder ='big', signed = False)
		return pw.decode('utf-16le')

	@staticmethod
	def encode_password(password):
		enc_pw = ''
		for c in password.encode('utf-16le'):
			temp = ord(c)
			temp = ((temp << 4)&0xff) | ((temp >> 4) &0xff)
			enc_pw += (temp ^ 0xA5).to_bytes(1, byteorder = 'big', signed = False) 
		return enc_pw

	@staticmethod
	def from_bytes(x, bbuff):
		return LOGIN7.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(x, buffer):
		login = LOGIN7()
		login.total_length = int.from_bytes(buffer.read(4), byteorder = 'little', signed = 'False')
		login.tds_version = int.from_bytes(buffer.read(4), byteorder = 'little', signed = 'False')
		login.packet_size = int.from_bytes(buffer.read(4), byteorder = 'little', signed = 'False')
		login.clientprogver = int.from_bytes(buffer.read(4), byteorder = 'little', signed = 'False')
		login.client_pid = int.from_bytes(buffer.read(4), byteorder = 'little', signed = 'False')
		login.connection_id = int.from_bytes(buffer.read(4), byteorder = 'little', signed = 'False')
		login.flags1 = int.from_bytes(buffer.read(1), byteorder = 'little', signed = 'False')
		login.flags2 = int.from_bytes(buffer.read(1), byteorder = 'little', signed = 'False')
		login.sql_type_flags = int.from_bytes(buffer.read(1), byteorder = 'little', signed = 'False')
		login.flags3 = int.from_bytes(buffer.read(1), byteorder = 'little', signed = 'False')
		login.timezone = int.from_bytes(buffer.read(4), byteorder = 'little', signed = 'False')
		login.collation = int.from_bytes(buffer.read(4), byteorder = 'little', signed = 'False')

		login.cliname_off = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.cliname_len = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.username_off = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.username_len = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.password_off = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.password_len = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.appname_off = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.appname_len = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.servername_off = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.servername_len = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.unused_1_off = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.unused_1_len = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.libname_off = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.libname_len = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.locale_off = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.locale_len = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')

		login.dbname_off = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		login.dbname_len = int.from_bytes(buffer.read(2), byteorder = 'little', signed = 'False')
		
		if login.cliname_off != 0:
			buffer.seek(login.cliname_off,0)
			login.cliname = buffer.read(login.cliname_len * 2).decode('utf-16le')
		
		if login.username_off != 0:
			buffer.seek(login.username_off,0)
			login.username = buffer.read(login.username_len * 2).decode('utf-16le')
		
		if login.password_off != 0:
			buffer.seek(login.password_off,0)
			login.password = LOGIN7.decode_password(buffer.read(login.password_len * 2))
		
		if login.appname_off != 0:
			buffer.seek(login.appname_off,0)
			login.appname = buffer.read(login.appname_len * 2).decode('utf-16le')
		
		if login.servername_off != 0:
			buffer.seek(login.servername_off,0)
			login.servername = buffer.read(login.servername_len * 2).decode('utf-16le')

		if login.unused_1_off != 0:
			buffer.seek(login.unused_1_off,0)
			login.unused = buffer.read(login.unused_1_len)
		
		if login.libname_off != 0:
			buffer.seek(login.libname_off,0)
			login.libname = buffer.read(login.libname_len * 2).decode('utf-16le')
		if login.locale_off != 0:
			buffer.seek(login.locale_off,0)
			login.locale = buffer.read(login.locale_len * 2).decode('utf-16le')
		if login.dbname_off != 0:
			buffer.seek(login.dbname_off,0)
			login.dbname = buffer.read(login.dbname_len * 2).decode('utf-16le')

		return login

	def __str__(self):
		return '%s : %s' % (self.username, self.password)

type2class = {
	#PacketType.SQL_BATCH : None,
	#PacketType.PRE_TDS7_LOGIN : None,
	#PacketType.RPC : None,
	#PacketType.TABULAR_RESULT : None,
	#PacketType.UNUSED_5 : None,
	#PacketType.ATTENTION_SIGNAL : None,
	#PacketType.BULK_LOAD_DATA : None,
	#PacketType.FEDERATED_AUTH_TOKEN : None,
	#PacketType.UNUSED_9 : None,
	#PacketType.UNUSED_10 : None,
	#PacketType.UNUSED_11 : None,
	#PacketType.UNUSED_12 : None,
	#PacketType.UNUSED_13 : None,
	#PacketType.TRANSACTION_MANAGER_REQ : None,
	#PacketType.UNUSED_15 : None,
	PacketType.LOGIN7 : LOGIN7,
	#PacketType.SSPI : None,
	PacketType.PRELOGIN : PRELOGIN,
}
type2class_inv = {v: k for k, v in type2class.items()}