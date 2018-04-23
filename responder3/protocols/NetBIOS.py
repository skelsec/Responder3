import io
import enum
import asyncio
import ipaddress

class DNSResponseCode(enum.Enum):
	NOERR = 0 #No error condition
	FORMATERR = 1 #Format error - The name server was  unable to interpret the query.
	SERVERERR = 2 #Server failure - The name server was unable to process this query due to a problem with the name server.
	NAMEERR = 3 #Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
	NOTIMPL = 4 #Not Implemented - The name server does not support the requested kind of query.
	REFUSED = 5 #Refused - The name server refuses to perform the specified operation for policy reasons.
	RESERVED6 = 6
	RESERVED7 = 7
	RESERVED8 = 8
	RESERVED9 = 9
	RESERVED10 = 10
	RESERVED11 = 11
	RESERVED12 = 12
	RESERVED13 = 13
	RESERVED14 = 14
	RESERVED15 = 15

class NBQType(enum.Enum):
	NB     = 0x0020   #NetBIOS general Name Service Resource Record
	NBSTAT = 0x0021   #NetBIOS NODE STATUS Resource Record (See NODE STATUS REQUEST)

class NBQClass(enum.Enum):
	IN = 0x0001 #Internet class


class NBRType(enum.Enum):
	A      = 0x0001   #IP address Resource Record (See REDIRECT NAME QUERY RESPONSE)
	NS     = 0x0002   #Name Server Resource Record (See REDIRECT NAME QUERY RESPONSE)
	NULL   = 0x000A #NULL Resource Record (See WAIT FOR ACKNOWLEDGEMENT RESPONSE)
	NB     = 0x0020   #NetBIOS general Name Service Resource Record (See NB_FLAGS and NB_ADDRESS, below)
	NBSTAT = 0x0021 #NetBIOS NODE STATUS Resource Record (See NODE STATUS RESPONSE)

class NBRClass(enum.Enum):
	IN = 0x0001 #Internet class

class NBTSNMFlags(enum.IntFlag):
	AUTHORATIVEANSWER = 0x40 #Authoritative Answer flag. Must be zero (0) if R flag of OPCODE is zero
	TRUNCATED = 0x20 #Truncation Flag.
	RECURSIONDESIRED = 0x10 #Recursion Desired Flag.
	RECURSIONAVAILABLE = 0x8 #Recursion Available Flag.
	BROADCAST  = 0x1 #Broadcast Flag. 1: packet was broadcast or multicast  0: unicast



#http://www.rfc-editor.org/rfc/rfc1002.txt
class NBTNSOpcode(enum.Enum):
	QUERY = 0
	REGISTRATION = 5
	RELEASE =  6
	WACK = 7
	REFRESH =  8

class NBTSResponse(enum.Enum):
	REQUEST  = 0
	RESPONSE = 1

class NBTNSPacket():
	def __init__(self):
		#HEADER
		self.NAME_TRN_ID = None #Transaction ID for Name Service Transaction. Requestor places a unique value for each active  transaction.  Responder puts NAME_TRN_ID value from request packet in response packet.
		self.RESPONSE = None
		self.NM_FLAGS = None
		self.OPCPDE = None
		self.RCODE = None #Result codes of request
		self.QDCOUNT = None #Unsigned 16 bit integer specifying the number of entries in the question section of a Name
		self.ANCOUNT = None #Unsigned 16 bit integer specifying the number of resource records in the answer section of a Name Service packet.
		self.NSCOUNT = None #Unsigned 16 bit integer specifying the number of resource records in the authority section of a Name Service packet.
		self.ARCOUNT = None #Unsigned 16 bit integer specifying the number of resource records in the additional records section of a Name Service packet.

		self.Questions = []
		self.Answers   = []
		self.Authorities = []
		self.Additionals = []

	async def from_streamreader(reader):
		data = await reader.read()
		return NBTNSPacket.from_bytes(data)

	def from_bytes(bbuff):
		return NBTNSPacket.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		packet = NBTNSPacket()
		packet.NAME_TRN_ID = buff.read(2)
		t = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		packet.RESPONSE = NBTSResponse((t >> 15))
		packet.OPCODE = NBTNSOpcode((t & 0x7800) >> 11)
		packet.NM_FLAGS = NBTSNMFlags((t & 0x7F0) >> 4)
		packet.RCODE = t & 0xF
		packet.QDCOUNT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False) 
		packet.ANCOUNT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False) 
		packet.NSCOUNT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False) 
		packet.ARCOUNT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False) 

		for i in range(0, packet.QDCOUNT):
			dnsq = NBQuestion.from_buffer(buff)
			packet.Questions.append(dnsq)

		
		for i in range(0, packet.ANCOUNT):
			dnsr = NBResource.from_buffer(buff)
			packet.Answers.append(dnsr)

		for i in range(0, packet.NSCOUNT):
			dnsr = NBResource.from_buffer(buff)
			packet.Answers.append(dnsr)

		for i in range(0, packet.ARCOUNT):
			dnsr = NBResource.from_buffer(buff)
			packet.Answers.append(dnsr)

		return packet

	def construct(self, TID, response, opcode, nmflags, rcode = 0, 
					questions= [], answers= [], authorities = [], additionals = []):
		self.NAME_TRN_ID = TID
		self.RESPONSE = response
		self.OPCODE   = opcode
		self.NM_FLAGS = nmflags
		self.RCODE    = rcode
		self.QDCOUNT = len(questions)
		self.ANCOUNT = len(answers)
		self.NSCOUNT = len(authorities)
		self.ARCOUNT = len(additionals)

		self.Questions   = questions
		self.Answers     = answers
		self.Authorities = authorities
		self.Additionals = additionals

	def to_bytes(self):
		t = self.NAME_TRN_ID
		#Flags part
		a = self.RCODE & 0xF
		a |= (self.NM_FLAGS << 4 ) & 0x7F0
		a |= (self.OPCODE.value << 11) & 0x7800
		a |= (self.RESPONSE.value << 15) & 0x8000
		t += a.to_bytes(2, byteorder = 'big', signed = False)
		#flags part end
		t += self.QDCOUNT.to_bytes(2, byteorder = 'big', signed = False)
		t += self.ANCOUNT.to_bytes(2, byteorder = 'big', signed = False)
		t += self.NSCOUNT.to_bytes(2, byteorder = 'big', signed = False)
		t += self.ARCOUNT.to_bytes(2, byteorder = 'big', signed = False)

		for q in self.Questions:
			t += q.to_bytes()

		for q in self.Answers:
			t += q.to_bytes()

		for q in self.Authorities:
			t += q.to_bytes()

		for q in self.Additionals:
			t += q.to_bytes()

		return t


	def __repr__(self):
		t  = '== NBTNSPacket ==\r\n'
		t += 'TransactionID %s\r\n' % self.NAME_TRN_ID.hex()
		t += 'RESPONSE : %s\r\n' % self.RESPONSE.name
		t += 'OPCODE   : %s\r\n' % self.OPCODE.name
		t += 'NM_FLAGS : %s\r\n' % repr(self.NM_FLAGS)
		t += 'RCODE    : %s\r\n' % self.RCODE
		t += 'QDCOUNT  : %s\r\n' % self.QDCOUNT
		t += 'ANCOUNT  : %s\r\n' % self.ANCOUNT
		t += 'NSCOUNT  : %s\r\n' % self.NSCOUNT
		t += 'ARCOUNT  : %s\r\n' % self.ARCOUNT

		for question in self.Questions:
			t+= repr(question)

		for answer in self.Answers:
			t+= repr(answer)

		return t


class NBQuestion():
	def __init__(self):
		self.QNAME = None
		self.QTYPE = None
		self.QCLASS = None

	def from_bytes(bbuff):
		return NBQuestion.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		qst = NBQuestion()
		qst.QNAME = NBName.from_buffer(buff)
		#print(repr(qst.QNAME))
		qst.QTYPE  = NBQType(int.from_bytes(buff.read(2), byteorder = 'big'))
		qst.QCLASS = NBQClass(int.from_bytes(buff.read(2), byteorder = 'big'))

		return qst

	def to_bytes(self):
		t  = self.QNAME.to_bytes()
		t += self.QTYPE.value.to_bytes(2, byteorder = 'big', signed = False)
		t += self.QCLASS.value.to_bytes(2, byteorder = 'big', signed = False)

		return t

	def construct(self, qname, qtype, qclass):
		self.QNAME     = qname
		self.QTYPE     = qtype
		self.QCLASS    = qclass

	def __repr__(self):
		t = '== NetBIOS Question ==\r\n'
		t+= 'QNAME:  %s\r\n' % self.QNAME
		t+= 'QTYPE:  %s\r\n' % self.QTYPE.name
		t+= 'QCLASS: %s\r\n' % self.QCLASS.name
		return t

class NBResource():
	def __init__(self):
		self.NAME     = None
		self.TYPE     = None
		self.CLASS    = None
		self.TTL      = None
		self.RDLENGTH = None
		self.RDATA    = None

	def from_bytes(bbuff):
		return NBResource.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		rs = NBResource()
		rs.NAME     = NBName.from_buffer(buff)
		rs.TYPE     = NBRType(int.from_bytes(buff.read(2), byteorder = 'big'))
		rs.CLASS    = NBRClass(int.from_bytes(buff.read(2), byteorder = 'big'))
		rs.TTL      = int.from_bytes(buff.read(4), byteorder = 'big')
		rs.RDLENGTH = int.from_bytes(buff.read(2), byteorder = 'big')
		trdata      = buff.read(rs.RDLENGTH)

		if rs.TYPE == NBRType.A and rs.QCLASS == NBRClass.IN:
			rs.RDATA = ipaddress.IPv4Address(trdata)

		#TODO for other types :)
		else:
			rs.RDATA = trdata

	
	def to_bytes(self):
		t  = self.NAME.to_bytes()
		t += self.TYPE.value.to_bytes(2, byteorder = 'big', signed = False)
		t += self.CLASS.value.to_bytes(2, byteorder = 'big', signed = False)
		t += self.TTL.to_bytes(4, byteorder = 'big', signed = False)
		t += self.RDLENGTH.to_bytes(2, byteorder = 'big', signed = False)
		t += self.RDATA

		return t
	
	def construct(self, name, rtype, ip, flags = 0x0000, ttl = 3000, rclass = NBRClass.IN):
		self.NAME     = name
		self.TYPE     = rtype
		self.CLASS    = rclass
		self.TTL      = ttl

		if self.TYPE == NBRType.NB and self.CLASS == NBRClass.IN:
			self.RDATA = flags.to_bytes(2, byteorder = 'big', signed = False)
			self.RDATA += ip.packed

		self.RDLENGTH = len(self.RDATA)

	def __repr__(self):
		t = '== NetBIOS Resource ==\r\n'
		t+= 'NAME:  %s\r\n' % self.NAME
		t+= 'TYPE:  %s\r\n' % self.TYPE.name
		t+= 'CLASS: %s\r\n' % self.CLASS.name
		t+= 'TTL: %s\r\n' % self.TTL
		t+= 'RDLENGTH: %s\r\n' % self.RDLENGTH
		t+= 'RDATA: %s\r\n' % repr(self.RDATA)
		return t

#https://msdn.microsoft.com/en-us/library/cc224454.aspx
class NBSuffixGroup(enum.Enum):
	MACHINE_GROUP   = 0x00
	MASTER_BROWSER  = 0x01
	BROWSER_SERVICE = 0x1E

	@classmethod
	def has_value(cls, value):
		return any(value == item.value for item in cls)

class NBSuffixUnique(enum.Enum):
	WORKSTATION   = 0x00
	DOMAIN        = 0x1B
	MACHINE_GROUP = 0x1D
	SERVER        = 0x20
	DOMAIN_CONTROLLER = 0x1C #guess from wireshark
	UNKNOWN_1     = 0x19
	UNKNOWN_2     = 0x48

	@classmethod
	def has_value(cls, value):
		return any(value == item.value for item in cls)

class NBName():
	def __init__(self):
		self.length = None
		self.name   = None #string
		self.suffix = None

	def from_bytes(bbuff):
		return NBName.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		name = NBName()
		name.length = int.from_bytes(buff.read(1), byteorder = 'big')
		if name.length == 0x20: #compressed_name
			temp = NBName.decode_NS(buff.read(name.length))
		else: #pointer, most likely
			ptr = int.from_bytes(buff.read(1), byteorder = 'big')
			pos = buff.tell()
			buff.seek(ptr, io.SEEK_SET)
			tlen = int.from_bytes(buff.read(1), byteorder = 'big')
			temp = NBName.decode_NS(buff.read(tlen))
			buff.seek(pos, io.SEEK_SET)
			#debug
			#pos = buff.tell()
			#print(buff.read().hex())
			#buff.seek(pos, io.SEEK_SET)

		name.name = temp[:-1].strip()
		if NBSuffixUnique.has_value(ord(temp[-1])):
			name.suffix = NBSuffixUnique(ord(temp[-1]))
		else:
			name.suffix = NBSuffixGroup(ord(temp[-1]))
		if name.length == 0x20:
			zero = buff.read(1)
		return name

	def construct(name, suffix = NBSuffixUnique.WORKSTATION):
		assert len(name) == 15, 'NBNames max size is 15 chars'
		nbname = NBName()
		nbname.suffix = suffix
		nbname.name   = name
		nbname.length = len(NBName.encode_NS(name, suffix.value))
		return name

	def to_bytes(self):
		t  = self.length.to_bytes(1, byteorder = 'big', signed = False)
		t += NBName.encode_NS(self.name, self.suffix.value)
		t += b'\x00'
		return t

	def encode_NS(name, suffix):
		#encoded http://www.ietf.org/rfc/rfc1001.txt
		name = name.encode()
		name = name.ljust(15, b' ')
		name = name.upper()
		name+= suffix.to_bytes(1, byteorder = 'big', signed = False)
		temp = b''
		for c in name:
			temp += (((c & 0xF0) >> 4) + 0x41).to_bytes(1, byteorder = 'big', signed = False)
			temp += ((c & 0x0F) + 0x41).to_bytes(1, byteorder = 'big', signed = False)
		return temp

	def decode_NS(encoded_name):
		#encoded http://www.ietf.org/rfc/rfc1001.txt
		name_raw = ''
		transform = [((i - 0x41)& 0x0F) for i in encoded_name]
		i = 0
		while i < len(transform):
			name_raw += chr(transform[i] << 4 | transform[i+1] ) 
			i+=2
		return name_raw

	def __repr__(self):
		t = '== NBName ==\r\n'
		t += 'name  : %s \r\n' % self.name
		t += 'suffix: %s \r\n' % repr(self.suffix)
		t += 'length: %s \r\n' % repr(self.length)
		return t