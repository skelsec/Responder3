import enum
import io
import socket
import asyncio
import ipaddress

from responder3.protocols.DNS import * 

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
        def __init__(self):
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

        @asyncio.coroutine
        def from_streamreader(reader):
                data = yield from reader.read()
                return LLMNRPacket.from_bytes(data)

        def from_bytes(bbuff):
                return LLMNRPacket.from_buffer(io.BytesIO(bbuff))

        def from_buffer(buff):
                packet = LLMNRPacket()

                packet.TransactionID = buff.read(2)
                temp = int.from_bytes(buff.read(2), byteorder = 'big', signed=False)

                packet.QR     = LLMNRResponse(temp >> 15)
                packet.Opcode = LLMNROpcode((temp & 0x7800) >> 11) 
                packet.FLAGS  = LLMNRFlags((temp & 0x7F0) >> 4)
                packet.Rcode  = DNSResponseCode(temp & 0xF)

                packet.QDCOUNT = int.from_bytes(buff.read(2), byteorder = 'big', signed=False)
                packet.ANCOUNT = int.from_bytes(buff.read(2), byteorder = 'big', signed=False)
                packet.NSCOUNT = int.from_bytes(buff.read(2), byteorder = 'big', signed=False)
                packet.ARCOUNT = int.from_bytes(buff.read(2), byteorder = 'big', signed=False)

                
                for i in range(0, packet.QDCOUNT):
                        dnsq = DNSQuestion.from_buffer(buff)
                        packet.Questions.append(dnsq)

                
                for i in range(0, packet.ANCOUNT):
                        dnsr = DNSResourceParser.from_buffer(buff)
                        packet.Answers.append(dnsr)

                for i in range(0, packet.NSCOUNT):
                        dnsr = DNSResourceParser.from_buffer(buff)
                        packet.Authorities.append(dnsr)

                for i in range(0, packet.ARCOUNT):
                        dnsr = DNSResourceParser.from_buffer(buff)
                        packet.Additionals.append(dnsr)

                return packet
                

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

                if len(self.Questions) > 0:
                        for question in self.Questions:
                                t+= repr(question)

                if len(self.Answers) > 0:
                        for answer in self.Answers:
                                t+= repr(answer)

                if len(self.Authorities) > 0:
                        for answer in self.Authorities:
                                t+= repr(answer)

                if len(self.Additionals) > 0:
                        for answer in self.Additionals:
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

        def construct(TID, response,  flags = 0, opcode = LLMNROpcode.DEFAULT, rcode = DNSResponseCode.NOERR, 
                                        questions= [], answers= [], authorities = [], additionals = []):
                
                packet = LLMNRPacket()
                packet.TransactionID = TID
                packet.QR      = response
                packet.Opcode  = opcode
                packet.FLAGS   = flags
                packet.Rcode   = rcode
                packet.QDCOUNT = len(questions)
                packet.ANCOUNT = len(answers)
                packet.NSCOUNT = len(authorities)
                packet.ARCOUNT = len(additionals)

                packet.Questions   = questions
                packet.Answers     = answers
                packet.Authorities = authorities
                packet.Additionals = additionals

                return packet