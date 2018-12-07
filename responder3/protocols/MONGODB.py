
# https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/
# https://docs.mongodb.com/manual/core/security-scram/#authentication-scram
# 
import enum
import bson
import io

def read_bson(buff):
	length_data = buff.read(4)
	length = int.from_bytes(length_data, byteorder = 'little', signed = False)
	return bson.loads(length_data + buff.read(length))


def buffer_peek(buff, length = 1):
	pos = buff.tell()
	temp = buff.read(length)
	buff.seek(pos, 0)
	return temp

def get_buffer_endpos(buff):
	pos = buff.tell()
	buff.seek(0, 2)
	pos_end = buff.tell()
	buff.seek(pos, 0)
	return pos_end

def get_buffer_size(buff):
	pos = buff.tell()
	buff.seek(0, 0)
	pos_start = buff.tell()
	buff.seek(0, 2)
	pos_end = buff.tell()
	buff.seek(pos, 0)

	return pos_end - pos_start

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

class Section0:
	def __init__(self):
		self.kind = 0
		self.body = None

	@staticmethod
	def from_bytes(bbuff):
		return Section0.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		section = Section0()
		section.kind = int.from_bytes(buff.read(1), byteorder = 'little', signed = False)
		section.body = read_bson(buff)
		return section

class Section1:
	def __init__(self):
		self.kind = 1
		self.length = None
		self.sequenceId = None
		self.datas = [] #Zero or more BSON objects #word from the author: WHAT THE FUCK??? WHY ARE YOU DOING THIS SHIT?	

	@staticmethod
	def from_bytes(bbuff):
		return Section1.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		section = Section1()
		section.kind = int.from_bytes(buff.read(1), byteorder = 'little', signed = False)
		section.length = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		section.sequenceId = read_cstring(buff)
		datas_len_pos = buff.tell() + section.length

		while buff.tell() <= datas_len_pos:
			bdata = read_bson(buff)
			section.datas.append(bdata)

		return section

class RequestOpcode(enum.Enum):
	OP_REPLY = 1 #Reply to a client request. responseTo is set.
	OP_UPDATE = 2001# 	Update document.
	OP_INSERT = 2002# 	Insert new document.
	RESERVED = 2003# 	Formerly used for OP_GET_BY_OID.
	OP_QUERY = 2004# 	Query a collection.
	OP_GET_MORE = 2005# 	Get more data from a query. See Cursors.
	OP_DELETE = 2006# 	Delete documents.
	OP_KILL_CURSORS = 2007# 	Notify database that the client has finished with the cursor.
	OP_COMMAND = 2010# 	Cluster internal protocol representing a command request.
	OP_COMMANDREPLY = 2011# 	Cluster internal protocol representing a reply to an OP_COMMAND.
	OP_MSG = 2013# 	Send a message using the format introduced in MongoDB 3.6.


class MongoMessageParser:
	def __init__(self):
		pass

	@staticmethod
	async def from_streamreader(reader):
		t_messageLength = await readexactly_or_exc(reader, 4, timeout = self.timeout)
		t_requestID = await readexactly_or_exc(reader, 4, timeout = self.timeout)
		t_responseTo = await readexactly_or_exc(reader, 4, timeout = self.timeout)
		t_opCode = await readexactly_or_exc(reader, 4, timeout = self.timeout)
		msg_type = RequestOpcode(int.from_bytes(t_opCode, byteorder = 'little', signed = False))
		msg_length = int.from_bytes(t_length, byteorder = 'little', signed = False)
		rlen = msg_length - 16
		t_data = await readexactly_or_exc(reader, rlen, timeout = self.timeout)
		return mongotype2class[msg_type].from_bytes(t_messageLength + t_requestID + t_responseTo + t_opCode)

class MsgHeader:
	def __init__(self):
		self.messageLength = None
		self.requestID = None
		self.responseTo = None
		self.opCode = None

	@staticmethod
	def from_bytes(bbuff):
		return MsgHeader.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		hdr = MsgHeader()
		hdr.messageLength = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		hdr.requestID = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		hdr.responseTo = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		hdr.opCode = RequestOpcode(int.from_bytes(buff.read(4), byteorder = 'litte', signed = False))
		return hdr


class OP_QUERYFlags(enum.IntFlag):
	Reserved = 0
	TailableCursor = 1
	SLAVE_OK = 2
	OPLOG_REPLAY = 3
	NO_CURSOR_TIMEOUT = 4
	AWAIT_DATA = 5
	EXHAUST = 6
	PARTIAL = 7


class OP_QUERY:
	def __init__(self):
		self.header = None
		self.flags = None
		self.fullCollectionName = None
		self.numberToSkip = None
		self.numberToReturn = None
		self.query = None
		self.returnFieldsSelector = None #OPTIONAL!

	@staticmethod
	def from_bytes(bbuff):
		return OP_QUERY.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = OP_QUERY()
		msg.header = MsgHeader.from_buffer(buff)
		msg.flags = OP_QUERYFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		msg.fullCollectionName = read_cstring(buff).decode()
		msg.numberToSkip = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		msg.numberToReturn = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		msg.query = read_bson(buff)
		if buff.tell() != get_buffer_endpos(buff)
			msg.returnFieldsSelector = read_bson(buff)

		return msg

class OP_MSGFlags(enum.IntFlag):
	checksumPresent = 0
	moreToCome = 1
	exhaustAllowed = 16


class OP_MSG:
	def __init__(self):
		self.header = None
		self.flagBits = None
		self.sections = None
		self.checksum = None

	@staticmethod
	def from_bytes(bbuff):
		return OP_MSG.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = OP_MSG()
		msg.header = MsgHeader.from_buffer(buff)
		msg.flagBits = OP_MSGFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		
		end_pos = get_buffer_endpos(buff)
		if msg.flagBits & OP_MSGFlags.checksumPresent:
			end_pos =- 4

		while buff.tell() != end_pos:
			kind = buffer_peek(buff)
			section = sectionkind2class[kind].from_buffer(buff)
			msg.sections.append(section)

		if msg.flagBits & OP_MSGFlags.checksumPresent:
			msg.checksum = buff.read(4)
		
		return msg

	def to_bytes(self):
		t = self.flagBits.to_bytes(4, byteorder = 'little', signed = False)
		for section in self.sections:
			t += section.to_bytes()

		if self.checksum:
			t += self.checksum.to_bytes(4, byteorder = 'little', signed = False)

		t = self.header.to_bytes() + t

		return t



class OP_REPLYFlags(enum.IntFlag):
	CursorNotFound = 0
	QueryFailure = 1
	ShardConfigStale = 2
	AwaitCapable = 3


class OP_REPLY:
	def __init__(self):
		self.header = None
		self.responseFlags = None
		self.cursorID = None
		self.startingFrom = None
		self.numberReturned = None
		self.documents = []

	@staticmethod
	def from_bytes(bbuff):
		return OP_MSG.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		msg = OP_MSG()
		msg.header = MsgHeader.from_buffer(buff)
		msg.responseFlags = OP_REPLYFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		msg.cursorID = int.from_bytes(buff.read(8), byteorder = 'little', signed = False)
		msg.startingFrom = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		msg.numberReturned = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		
		end_pos = get_buffer_endpos(buff)
		while buff.tell() <= end_pos:
			document = read_document(buff)
			msg.documents.append(document)

		return msg

	def to_bytes(self):
		t = self.header.to_bytes()
		t += self.responseFlags.to_bytes(4, byteorder = 'little', signed = False)
		t += self.cursorID.to_bytes(8, byteorder = 'little', signed = False)
		t += self.startingFrom.to_bytes(4, byteorder = 'little', signed = False)
		t += self.numberReturned.to_bytes(4, byteorder = 'little', signed = False)
		for document in self.documents:
			t += bson.dumps(document)

		return t


mongotype2class = {
	RequestOpcode.OP_REPLY : OP_REPLY,
	RequestOpcode.OP_UPDATE : None,
	RequestOpcode.OP_INSERT : None,
	RequestOpcode.RESERVED : None,
	RequestOpcode.OP_QUERY : OP_QUERY,
	RequestOpcode.OP_GET_MORE : None,
	RequestOpcode.OP_DELETE : None,
	RequestOpcode.OP_KILL_CURSORS : None,
	RequestOpcode.OP_COMMAND : None,
	RequestOpcode.OP_COMMANDREPLY : None,
	RequestOpcode.OP_MSG : OP_MSG,

}

sectionkind2class = {
	0 : Section0,
	1 : Section1,
}