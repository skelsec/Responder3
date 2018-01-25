import io
import enum
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

	def toBytes(self):
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
			t += q.toBytes()

		for q in self.Answers:
			t += q.toBytes()

		for q in self.Authorities:
			t += q.toBytes()

		for q in self.Additionals:
			t += q.toBytes()

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
		self.QNAME_LEN = None
		self.QNAME = None
		self.QTYPE = None
		self.QCLASS = None

	def from_bytes(bbuff):
		return NBQuestion.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		qst = NBQuestion()
		qst.QNAME_LEN = buff.read(1)[0]
		qst.QNAME = ''
		if qst.QNAME_LEN == 32:
			qst.decode_NS(buff.read(qst.QNAME_LEN))
			buff.read(1)
		else:
			qst.QNAME  = buff.read(qst.QNAME_LEN).decode()
			buff.read(1)

		qst.QTYPE  = NBQType(int.from_bytes(buff.read(2), byteorder = 'big'))
		qst.QCLASS = NBQClass(int.from_bytes(buff.read(2), byteorder = 'big'))

		return qst

	def toBytes(self):
		t  = self.QNAME_LEN.to_bytes(1, byteorder = 'big')
		t += self.QNAME.encode() + b'\x00'
		t += self.QTYPE.value.to_bytes(2, byteorder = 'big', signed = False)
		t += self.QCLASS.value.to_bytes(2, byteorder = 'big', signed = False)

		return t

	def construct(self, qname, qtype, qclass):
		self.QNAME_LEN = len(qname.encode()) + 1 #ending zero!
		self.QNAME     = qname
		self.QTYPE     = qtype
		self.QCLASS    = qclass

	def decode_NS(self, encoded_name):
		#encoded http://www.ietf.org/rfc/rfc1001.txt
		transform = [((i - 0x41)& 0x0F) for i in encoded_name]
		i = 0
		while i < len(transform):
			self.QNAME += chr(transform[i] << 4 | transform[i+1] ) 
			i+=2

		#removing trailing x00 and trailing spaces
		self.QNAME = self.QNAME.replace('\x00','').strip()

	def __repr__(self):
		t = '== NetBIOS Question ==\r\n'
		t+= 'QNAME:  %s\r\n' % self.QNAME
		t+= 'QTYPE:  %s\r\n' % self.QTYPE.name
		t+= 'QCLASS: %s\r\n' % self.QCLASS.name
		return t

class NBResource():
	def __init__(self):
		self.NAME_LEN = None
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
		rs.NAME_LEN = buff.read(1)[0] + 1
		rs.NAME     = buff.read(rs.NAME_LEN).decode()
		rs.TYPE     = NBRType(int.from_bytes(buff.read(2), byteorder = 'big'))
		rs.CLASS    = NBRClass(int.from_bytes(buff.read(2), byteorder = 'big'))
		rs.TTL      = int.from_bytes(buff.read(4), byteorder = 'big')
		rs.RDLENGTH = int.from_bytes(buff.read(2), byteorder = 'big')
		trdata      = buff.read(rs.RDLENGTH)

		if rs.TYPE == DNSType.A and rs.QCLASS == NBRClass.IN:
			rs.RDATA = ipaddress.IPv4Address(trdata)

		#TODO for other types :)
		else:
			rs.RDATA = trdata

	
	def toBytes(self):
		t  = self.NAME_LEN.to_bytes(1, byteorder = 'big', signed = False)
		t += self.NAME
		t += self.TYPE.value.to_bytes(2, byteorder = 'big', signed = False)
		t += self.CLASS.value.to_bytes(2, byteorder = 'big', signed = False)
		t += self.TTL.to_bytes(4, byteorder = 'big', signed = False)
		t += self.RDLENGTH.to_bytes(2, byteorder = 'big', signed = False)
		t += self.RDATA

		return t
	
	def construct(self, name, rtype, ip, flags = 0x0000, ttl = 3000, rclass = NBRClass.IN):

		self.NAME     = b''
		self.encode_NS(name.encode())
		self.NAME_LEN = len(self.NAME)
		self.NAME += b'\x00'
		self.TYPE     = rtype
		self.CLASS    = rclass
		self.TTL      = ttl

		if self.TYPE == NBRType.NB and self.CLASS == NBRClass.IN:
			self.RDATA = flags.to_bytes(2, byteorder = 'big', signed = False)
			self.RDATA += ip.packed


		self.RDLENGTH = len(self.RDATA)

	def encode_NS(self, name):
		#encoded http://www.ietf.org/rfc/rfc1001.txt
		for c in name:
			self.NAME += (((c & 0xF0) >> 4) + 0x41).to_bytes(1, byteorder = 'big', signed = False)
			self.NAME += ((c & 0x0F) + 0x41).to_bytes(1, byteorder = 'big', signed = False)

		
	

	def __repr__(self):
		t = '== NetBIOS Resource ==\r\n'
		t+= 'NAME:  %s\r\n' % self.NAME
		t+= 'TYPE:  %s\r\n' % self.TYPE.name
		t+= 'CLASS: %s\r\n' % self.CLASS.name
		t+= 'TTL: %s\r\n' % self.TTL
		t+= 'RDLENGTH: %s\r\n' % self.RDLENGTH
		t+= 'RDATA: %s\r\n' % repr(self.RDATA)
		return t
