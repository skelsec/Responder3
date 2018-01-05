import enum
import io
import socket
import ipaddress

from responder3.newpackets.DNS import * 

#https://tools.ietf.org/html/rfc1035
#https://tools.ietf.org/html/rfc4795
class LLMNRFlags(enum.IntFlag):
	CONFILCT   = 0x40
	TRUNCATION = 0x20
	TENTATIVE  = 0x10
	RESERVED1  = 0x8
	RESERVED2  = 0x4
	RESERVED3  = 0x2
	RESERVED4  = 0x1

class LLMNROpcode(enum.Enum):
	DEFAULT = 0x0000

class LLMNRResponse(enum.Enum):
	REQUEST  = 0
	RESPONSE = 1

class LLMNRPacket():
	def __init__(self, data = None):
		self.TransactionID = None
		self.QR = None
		self.Opcode = None
		self.FLAGS = None
		self.Rcode = None
		self.QDCOUNT = None
		self.ANCOUNT = None
		self.NSCOUNT = None
		self.ARCOUNT = None

		self.Questions = []
		self.Answers   = []
		self.Authorities = []
		self.Additionals = []



		if data is not None:
			self.parse(data)

	def parse(self, data):
		self.TransactionID = data.read(2)
		temp = int.from_bytes(data.read(2), byteorder = 'big', signed=False)

		self.QR = LLMNRResponse(temp >> 15)
		self.Opcode = LLMNROpcode((temp << 1) >> 12) 
		self.FLAGS = LLMNRFlags((temp << 5) >> 9)
		self.Rcode = DNSResponseCode(temp & 0xF)

		self.QDCOUNT = int.from_bytes(data.read(2), byteorder = 'big', signed=False)
		self.ANCOUNT = int.from_bytes(data.read(2), byteorder = 'big', signed=False)
		self.NSCOUNT = int.from_bytes(data.read(2), byteorder = 'big', signed=False)
		self.ARCOUNT = int.from_bytes(data.read(2), byteorder = 'big', signed=False)

		
		for i in range(0, self.QDCOUNT):
			dnsq = DNSQuestion(data)
			self.Questions.append(dnsq)

		
		for i in range(0, self.ANCOUNT):
			dnsr = DNSResource(data)
			self.Answers.append(dnsr)

		for i in range(0, self.NSCOUNT):
			dnsr = DNSResource(data)
			self.Answers.append(dnsr)

		for i in range(0, self.ARCOUNT):
			dnsr = DNSResource(data)
			self.Answers.append(dnsr)
		

	def __repr__(self):
		t = '== LLMNRPacket ==\r\n'
		t+= 'TransactionID:  %s\r\n' % self.TransactionID.hex()
		t+= 'QR:  %s\r\n' % self.QR.name
		t+= 'Opcode: %s\r\n' % self.Opcode.name
		t+= 'FLAGS: %s\r\n' % repr(self.FLAGS)
		t+= 'Rcode: %s\r\n' % self.Rcode.name
		t+= 'QDCOUNT: %s\r\n' % self.QDCOUNT
		t+= 'ANCOUNT: %s\r\n' % self.ANCOUNT
		t+= 'NSCOUNT: %s\r\n' % self.NSCOUNT
		t+= 'ARCOUNT: %s\r\n' % self.ARCOUNT

		for question in self.Questions:
			t+= repr(question)

		for answer in self.Answers:
			t+= repr(answer)

		return t

	def toBytes(self):
		t = b''
		t += self.TransactionID

		a  = self.Rcode.value
		a |= (self.FLAGS << 4 ) & 0x7F0
		a |= (self.Opcode.value << 11) & 0x7800
		a |= (self.QR.value << 15) & 0x8000
		t += a.to_bytes(2, byteorder = 'big', signed = False)

		t += self.QDCOUNT.to_bytes(2, byteorder = 'big', signed=False)
		t += self.ANCOUNT.to_bytes(2, byteorder = 'big', signed=False)
		t += self.NSCOUNT.to_bytes(2, byteorder = 'big', signed=False)
		t += self.ARCOUNT.to_bytes(2, byteorder = 'big', signed=False)

		for q in self.Questions:
			t += q.toBytes()

		for q in self.Answers:
			t += q.toBytes()

		for q in self.Authorities:
			t += q.toBytes()

		for q in self.Additionals:
			t += q.toBytes()

		return t

	def construct(self, TID, response,  flags = 0, opcode = LLMNROpcode.DEFAULT, rcode = DNSResponseCode.NOERR, 
					questions= [], answers= [], authorities = [], additionals = []):
		self.TransactionID = TID
		self.QR      = response
		self.Opcode  = opcode
		self.FLAGS   = flags
		self.Rcode   = rcode
		self.QDCOUNT = len(questions)
		self.ANCOUNT = len(answers)
		self.NSCOUNT = len(authorities)
		self.ARCOUNT = len(additionals)

		self.Questions   = questions
		self.Answers     = answers
		self.Authorities = authorities
		self.Additionals = additionals