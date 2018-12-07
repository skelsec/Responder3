# https://dev.mysql.com/doc/internals/en/connection-phase.html
# https://dev.mysql.com/doc/internals/en/mysql-packet.html

"""
everyone has a price paid in fortune or freedom 
every single device a grenade for fortune or freedom 
"""

import io
import enum

from responder3.core.asyncio_helpers import *

def get_buffer_endpos(buff):
	pos = buff.tell()
	buff.seek(0, 2)
	pos_end = buff.tell()
	buff.seek(pos, 0)
	return pos_end

def read_cstring(buff):
	# TODO: make this better
	temp = b''
	end_pos = get_buffer_endpos(buff)
	while buff.tell() <= end_pos:
		c = buff.read(1)
		temp += c
		if c == b'\x00':
			break

	if temp[-1:] != b'\x00':
		return None
	return temp

class MYSQLSessionStatus(enum.Enum):
	INITIAL_HANDSHAKE = 0
	AUTHENTICATION_SWITCH = 1

class MYSQLAuthType(enum.Enum):
	PLAIN = 'PLAIN' # https://dev.mysql.com/doc/internals/en/clear-text-authentication.html
	OLD = 'OLD' # https://dev.mysql.com/doc/internals/en/old-password-authentication.html
	SECURE = 'SECURE' # https://dev.mysql.com/doc/internals/en/secure-password-authentication.html



class CapabilityFlags(enum.IntFlag):
	LONG_PASSWORD = 0x00000001
	FOUND_ROWS = 0x00000002
	LONG_FLAG = 0x00000004
	CONNECT_WITH_DB = 0x00000008
	NO_SCHEMA = 0x00000010
	COMPRESS = 0x00000020
	ODBC = 0x00000040
	LOCAL_FILES = 0x00000080
	IGNORE_SPACE = 0x00000100
	PROTOCOL_41 = 0x00000200 #CLIENT_CHANGE_USER
	INTERACTIVE = 0x00000400
	SSL = 0x00000800
	IGNORE_SIGPIPE = 0x00001000
	TRANSACTIONS = 0x00002000
	RESERVED = 0x00004000
	SECURE_CONNECTION = 0x00008000
	MULTI_STATEMENTS = 0x00010000
	MULTI_RESULTS = 0x00020000
	PS_MULTI_RESULTS = 0x00040000
	PLUGIN_AUTH = 0x00080000
	CONNECT_ATTRS = 0x00100000
	PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
	CAN_HANDLE_EXPIRED_PASSWORDS = 0x00400000
	SESSION_TRACK = 0x00800000
	DEPRECATE_EOF = 0x01000000

class StatusFlags(enum.IntFlag):
	IN_TRANS = 0x0001    #a transaction is active
	AUTOCOMMIT = 0x0002  #auto-commit is enabled
	MORE_RESULTS_EXISTS = 0x0008 	 
	NO_GOOD_INDEX_USED = 0x0010 	 
	NO_INDEX_USED = 0x0020 	 
	CURSOR_EXISTS = 0x0040 #Used by Binary Protocol Resultset to signal that COM_STMT_FETCH must be used to fetch the row-data.
	LAST_ROW_SENT = 0x0080 	 
	DB_DROPPED = 0x0100 	 
	NO_BACKSLASH_ESCAPES = 0x0200 	 
	METADATA_CHANGED = 0x0400 	 
	QUERY_WAS_SLOW = 0x0800 	 
	PS_OUT_PARAMS = 0x1000 	 
	IN_TRANS_READONLY = 0x2000 #in a read-only transaction
	SESSION_STATE_CHANGED = 0x4000 #connection state information has changed

class CharacterSet(enum.Enum):
	big5_chinese_ci     =   1
	dec8_swedish_ci     =   3
	cp850_general_ci    =   4
	hp8_english_ci      =   6
	koi8r_general_ci    =   7
	latin1_swedish_ci   =   8
	latin2_general_ci   =   9
	swe7_swedish_ci     =  10
	ascii_general_ci    =  11
	ujis_japanese_ci    =  12
	sjis_japanese_ci    =  13
	hebrew_general_ci   =  16
	tis620_thai_ci      =  18
	euckr_korean_ci     =  19
	koi8u_general_ci    =  22
	gb2312_chinese_ci   =  24
	greek_general_ci    =  25
	cp1250_general_ci   =  26
	gbk_chinese_ci      =  28
	latin5_turkish_ci   =  30
	armscii8_general_ci =  32
	utf8_general_ci     =  33
	ucs2_general_ci     =  35
	cp866_general_ci    =  36
	keybcs2_general_ci  =  37
	macce_general_ci    =  38
	macroman_general_ci =  39
	cp852_general_ci    =  40
	latin7_general_ci   =  41
	cp1251_general_ci   =  51
	utf16_general_ci    =  54
	utf16le_general_ci  =  56
	cp1256_general_ci   =  57
	cp1257_general_ci   =  59
	utf32_general_ci    =  60
	binary              =  63
	geostd8_general_ci  =  92
	cp932_japanese_ci   =  95
	eucjpms_japanese_ci =  97
	gb18030_chinese_ci  = 248
	utf8mb4_0900_ai_ci  = 255

class HandshakeV10:
	def __init__(self):
		self.payload_length = None
		self.sequence_id = None
		self.protocol_version = 10
		self.server_version = None
		self.connection_id = None
		self.auth_plugin_data_part_1 = None
		self.filler = b'\x00'
		self.capability_flags = None
		self.character_set = None
		self.status_flags = None
		#self.capability_flags_2 = None
		#very optional XD
		self.length_of_auth_plugin_data = None
		self.reserved = b'\x00' * 10
		self.auth_plugin_data_part_2 = None
		self.auth_plugin_name = None

	@staticmethod
	def from_bytes(bbuff):
		return HandshakeV10.from_buffer(io.BytesIO(bbuff))

	# TODO: more processing of data
	@staticmethod
	def from_buffer(buff):
		resp = HandshakeV10() 
		resp.payload_length = int.from_bytes(buff.read(3),byteorder = 'little', signed = False)
		resp.sequence_id = int.from_bytes(buff.read(1),byteorder = 'little', signed = False)
		return resp

	def to_bytes(self):
		t = self.protocol_version.to_bytes(1, byteorder = 'little', signed = False)
		t += self.server_version.encode('ascii') + b'\x00'
		t += self.connection_id.to_bytes(4, byteorder = 'little', signed = False)
		t += self.auth_plugin_data_part_1.encode('ascii') + b'\x00'
		#t += self.filler
		flags = self.capability_flags.to_bytes(4, byteorder = 'little', signed = False)
		t += flags[:2]
		t += self.character_set.value.to_bytes(1, byteorder = 'little', signed = False)
		t += self.status_flags.to_bytes(2, byteorder = 'little', signed = False)
		t += flags[-2:]
		if self.capability_flags & CapabilityFlags.PLUGIN_AUTH:
			t += self.length_of_auth_plugin_data.to_bytes(1, byteorder = 'little', signed = False)
		else:
			t += b'\x00'
		t += self.reserved

		#if capability_flags & SECURE_CONNECTION:
		if self.auth_plugin_data_part_2:
			t += self.auth_plugin_data_part_2.encode() + b'\x00'

		if self.capability_flags & CapabilityFlags.PLUGIN_AUTH:
			t += self.auth_plugin_name.encode() + b'\x00'

		self.payload_length = len(t)
		t = self.sequence_id.to_bytes(1, byteorder = 'little', signed = False) + t
		t = self.payload_length.to_bytes(3, byteorder = 'little', signed = False)  + t
		return t

class HandshakeV10_New(HandshakeV10):
	def __init__(self, server_version, salt_1, salt_2, connection_id = 0, sequence_id = 0):
		HandshakeV10.__init__(self)
		self.sequence_id = sequence_id
		self.server_version = server_version
		self.connection_id = connection_id
		self.auth_plugin_data_part_1 = salt_1
		self.character_set = CharacterSet.utf8_general_ci
		self.status_flags = StatusFlags.AUTOCOMMIT
		self.auth_plugin_data_part_2 = salt_2

		#self.capability_flags = CapabilityFlags.RESERVED | CapabilityFlags.CONNECT_WITH_DB | \
		#	CapabilityFlags.LONG_PASSWORD | CapabilityFlags.PROTOCOL_41 | CapabilityFlags.LONG_FLAG | \
		#	CapabilityFlags.TRANSACTIONS | CapabilityFlags.SECURE_CONNECTION

		self.capability_flags =  CapabilityFlags.CONNECT_WITH_DB | \
			CapabilityFlags.PROTOCOL_41 | CapabilityFlags.LONG_FLAG | \
			CapabilityFlags.TRANSACTIONS


class HandshakeV10_Clear(HandshakeV10):
	def __init__(self, server_version, salt_1, connection_id = 0, sequence_id = 0):
		HandshakeV10.__init__(self)
		self.sequence_id = sequence_id
		self.server_version = server_version
		self.connection_id = connection_id
		self.auth_plugin_data_part_1 = salt_1
		self.character_set = CharacterSet.utf8_general_ci
		self.status_flags = StatusFlags.AUTOCOMMIT
		self.auth_plugin_data_part_2 = None
		self.auth_plugin_name = 'mysql_clear_password'
		self.length_of_auth_plugin_data = 0

		self.capability_flags =  CapabilityFlags.CONNECT_WITH_DB | \
			CapabilityFlags.PROTOCOL_41 | CapabilityFlags.LONG_FLAG | \
			CapabilityFlags.TRANSACTIONS | CapabilityFlags.PLUGIN_AUTH | CapabilityFlags.SECURE_CONNECTION


class HandshakeV9:
	def __init__(self):
		self.payload_length = None
		self.sequence_id = None
		self.protocol_version = 9
		self.server_version = None
		self.connection_id = None
		self.scramble = None

	def to_bytes(self):
		t = self.protocol_version.to_bytes(1, byteorder = 'little', signed = False)
		t += self.server_version.encode('ascii') + b'\x00'
		t += self.connection_id.to_bytes(4, byteorder = 'little', signed = False)
		t += self.scramble.encode('ascii') + b'\x00'

		self.payload_length = len(t)
		t = self.sequence_id.to_bytes(1, byteorder = 'little', signed = False) + t
		t = self.payload_length.to_bytes(3, byteorder = 'little', signed = False)  + t
		return t


class HandshakeResponse41:
	def __init__(self):
		self.payload_length = None
		self.sequence_id = None
		self.capability_flags = None
		self.max_packet_size = None
		self.character_set = None
		self.reserved = b'\x00' * 23
		self.username = None
		self.length_of_auth_response = None
		self.auth_response = None
		self.database = None
		self.auth_plugin_name = None
		self.length_of_all_key_values = None
		self.key_values = {}

	def to_bytes(self):
		t = self.capability_flags.to_bytes(4, byteorder = 'little', signed = False)
		t += self.max_packet_size.to_bytes(4, byteorder = 'little', signed = False)
		t += self.character_set.value.to_bytes(1, byteorder = 'little', signed = False)
		t += self.reserved
		t += self.username.encode('ascii') + b'\x00'
		
		if self.auth_response:
			t += self.length_of_auth_response.to_bytes(1, byteorder = 'little', signed = False)
			t += self.auth_response.encode() + b'\x00'
		else:
			t += b'\x00'
			t += self.auth_plugin_name.encode() + b'\x00'

		self.payload_length = len(t)
		t = self.sequence_id.to_bytes(1, byteorder = 'little', signed = False) + t
		t = self.payload_length.to_bytes(3, byteorder = 'little', signed = False)  + t
		return t

	@staticmethod
	def from_bytes(bbuff):
		return HandshakeResponse41.from_buffer(io.BytesIO(bbuff))

	# TODO: more processing of data
	@staticmethod
	def from_buffer(buff):
		resp = HandshakeResponse41()
		resp.payload_length = int.from_bytes(buff.read(3),byteorder = 'little', signed = False)
		resp.sequence_id = int.from_bytes(buff.read(1),byteorder = 'little', signed = False)
		resp.capability_flags = CapabilityFlags(int.from_bytes(buff.read(4),byteorder = 'little', signed = False))
		resp.max_packet_size = int.from_bytes(buff.read(4),byteorder = 'little', signed = False)
		resp.character_set = CharacterSet(int.from_bytes(buff.read(1),byteorder = 'little', signed = False))
		resp.reserved = buff.read(23)
		resp.username = read_cstring(buff).decode()
		resp.length_of_auth_response = int.from_bytes(buff.read(1),byteorder = 'little', signed = False)
		print(resp.length_of_auth_response)
		if resp.length_of_auth_response > 0:
			resp.auth_response = buff.read(resp.length_of_auth_response)

		# TODO: more processing of data
		resp.database = None
		resp.auth_plugin_name = None
		resp.length_of_all_key_values = None
		resp.key_values = {}

		return resp

class HandshakeResponse41_test(HandshakeResponse41):
	def __init__(self, sequence_id):
		HandshakeResponse41.__init__(self)
		self.sequence_id = sequence_id
		self.capability_flags = CapabilityFlags(0x01fea205)
		self.max_packet_size = 1073741824
		self.character_set = CharacterSet(255)
		self.username = 'admin'
		self.auth_plugin_name = 'mysql_clear_password'

class HandshakeResponse320:
	def __init__(self):
		self.payload_length = None
		self.sequence_id = None
		self.capability_flags = None
		self.max_packet_size = None
		self.username = None
		self.auth_response = None
		self.database = None

class SSLRequest:
	def __init__(self):
		self.payload_length = None
		self.sequence_id = None
		self.capability_flags = None
		self.max_packet_size = None
		self.character_set = None
		self.reserved = None

class AuthSwitchRequest:
	def __init__(self, sequence_id):
		self.payload_length = None
		self.sequence_id = sequence_id
		self.status = b'\xfe'
		self.plugin_name = None
		self.auth_plugin_data = None

	def to_bytes(self):
		t = self.status
		t += self.plugin_name.encode('ascii') + b'\x00'
		if self.auth_plugin_data:
			t += self.auth_plugin_data.encode('ascii')
		t += b'\x00'

		self.payload_length = len(t)
		t = self.sequence_id.to_bytes(1, byteorder = 'little', signed = False) + t
		t = self.payload_length.to_bytes(3, byteorder = 'little', signed = False)  + t
		return t

class AuthSwitchRequest_Clear(AuthSwitchRequest):
	def __init__(self, sequence_id):
		AuthSwitchRequest.__init__(self, sequence_id)
		self.payload_length = None
		self.status = b'\xfe'
		self.plugin_name = 'mysql_clear_password'
		self.auth_plugin_data = None

class AuthSwitchRequest_Old(AuthSwitchRequest):
	def __init__(self, sequence_id, salt):
		AuthSwitchRequest.__init__(self, sequence_id)
		self.payload_length = None
		self.status = b'\xfe'
		self.plugin_name = 'mysql_old_password'
		self.auth_plugin_data = salt


class OldAuthSwitchRequest:
	def __init__(self):
		self.payload_length = None
		self.sequence_id = sequence_id
		self.status = b'\xfe'

class AuthSwitchResponse:
	def __init__(self):
		self.payload_length = None
		self.sequence_id = None
		self.auth_plugin_data = None

	@staticmethod
	def from_bytes(bbuff):
		return AuthSwitchResponse.from_buffer(io.BytesIO(bbuff))

	# TODO: more processing of data
	@staticmethod
	def from_buffer(buff):
		resp = AuthSwitchResponse()
		resp.payload_length = int.from_bytes(buff.read(3),byteorder = 'little', signed = False)
		resp.sequence_id = int.from_bytes(buff.read(1),byteorder = 'little', signed = False)
		resp.auth_plugin_data = buff.read(-1)
		return resp


class MYSQLMessageParser:
	def __init__(self, mysql_session):
		self.session = mysql_session

	# https://dev.mysql.com/doc/internals/en/mysql-packet.html
	async def from_streamreader(self, reader):
		t_length = await readexactly_or_exc(reader, 3)
		length = int.from_bytes(t_length,byteorder = 'little', signed = False) + 1
		data = await readexactly_or_exc(reader, length)
		if self.session.status == MYSQLSessionStatus.INITIAL_HANDSHAKE:
			return HandshakeResponse41.from_bytes(t_length + data)
		elif self.session.status == MYSQLSessionStatus.AUTHENTICATION_SWITCH:
			return AuthSwitchResponse.from_bytes(t_length + data)
		else:
			return data