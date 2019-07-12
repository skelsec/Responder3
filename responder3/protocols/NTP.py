#https://tools.ietf.org/html/rfc5905
import io
import enum
import math
import random
import datetime
import ipaddress

"""
DISCLAIMER: DO NOT USE IT FOR MISSION-CRITICAL ENVIRONMENTS OR YOU WILL BE POTATO
SERIOUSLY!!!!! THE PRECISION IS BASED ON FLOATS FOR DATETIME, THE LOGARITHMICAL 
CALCULATIONS COULD YIELD SMALL ERRORS IN UNEXPECTED WAYS. NOT TO MENTION MY IDEAS OF PRECISION
"""

NTPEpoch = datetime.datetime(1900,1,1)

NTPStratumReferenceClock = {
	'GOES' : 'Geosynchronous Orbit Environment Satellite',
	'GPS'  : 'Global Position System',
	'GAL'  : 'Galileo Positioning System',
	'PPS'  : 'Generic pulse-per-second',
	'IRIG' : 'Inter-Range Instrumentation Group',                 
	'WWVB' : 'LF Radio WWVB Ft. Collins, CO 60 kHz',              
	'DCF'  : 'LF Radio DCF77 Mainflingen, DE 77.5 kHz',           
	'HBG'  : 'LF Radio HBG Prangins, HB 75 kHz',                  
	'MSF'  : 'LF Radio MSF Anthorn, UK 60 kHz',                   
	'JJY'  : 'LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz',
	'LORC' : 'MF Radio LORAN C station, 100 kHz',                 
	'TDF'  : 'MF Radio Allouis, FR 162 kHz',                      
	'CHU'  : 'HF Radio CHU Ottawa, Ontario',                      
	'WWV'  : 'HF Radio WWV Ft. Collins, CO',                      
	'WWVH' : 'HF Radio WWVH Kauai, HI',                           
	'NIST' : 'NIST telephone modem',                              
	'ACTS' : 'NIST telephone modem',                              
	'USNO' : 'USNO telephone modem',                              
	'PTB'  : 'European telephone modem',      
}

class NTPProtocolType(enum.Enum):
	TCP = enum.auto()
	UDP = enum.auto()

class NTPLeapIndicator(enum.Enum):
	NO_WARNING = 0
	LAST_61    = 1
	LAST_59    = 2
	UNKNOWN    = 3

class NTPMode(enum.Enum):
	RESERVED = 0
	SYMMETRIC_ACTIVE = 1
	SYMMETRIC_PASSIVE = 2
	CLIENT = 3
	SERVER = 4
	BROADCAST = 5
	NTP_CONTROL_MESSAGE = 6
	RESERVED_2 = 7

class NTPStratum(enum.Enum):
	UNSPECIFIED = 0
	PRIMARY_SERVER = 1
	SECONDARY_SERVER    = 2
	SECONDARY_SERVER_1  = 3
	SECONDARY_SERVER_2  = 4
	SECONDARY_SERVER_3  = 5
	SECONDARY_SERVER_4  = 6
	SECONDARY_SERVER_5  = 7
	SECONDARY_SERVER_6  = 8
	SECONDARY_SERVER_7  = 9
	SECONDARY_SERVER_8  = 10
	SECONDARY_SERVER_9  = 11
	SECONDARY_SERVER_10 = 12
	SECONDARY_SERVER_11 = 13
	SECONDARY_SERVER_12 = 14
	SECONDARY_SERVER_13 = 15
	UNSYNCHRONIZED = 16
	#reserved 17-255
	RESERVED = 17

class NTPShort():
	def __init__(self):
		self.Seconds  = None
		self.Fraction = None

	def from_bytes(bbuff):
		return NTPShort.from_buffer(io.BytesIO(bbuff))
	
	def from_buffer(buff):
		s = NTPShort()
		s.Seconds  = int.from_bytes(buff.read(2), byteorder='big', signed = False)
		s.Fraction = int.from_bytes(buff.read(2), byteorder='big', signed = False)
		return s

	def to_bytes(self):
		t  = self.Seconds.to_bytes(2, byteorder = 'big', signed = False)
		t += self.Fraction.to_bytes(2, byteorder = 'big', signed = False)
		return t

	def from_float(f):
		frac, tot = math.modf(f)
		s = NTPShort()
		s.Seconds = int(tot)
		fs, ts = math.modf(frac*(2**16))
		s.Fraction = int(ts)
		return s

	def total(self):
		return float(self.Seconds) + float(self.Fraction / 2**16 )

class NTPTimeStamp():
	def __init__(self):
		self.Seconds  = None
		self.Fraction = None

	def from_bytes(bbuff):
		return NTPTimeStamp.from_buffer(io.BytesIO(bbuff))
	def from_buffer(buff):
		s = NTPTimeStamp()
		s.Seconds = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		s.Fraction = int.from_bytes(buff.read(4), byteorder='big', signed = False)
		return s

	def to_bytes(self):
		t  = self.Seconds.to_bytes(4, byteorder = 'big', signed = False)
		t += self.Fraction.to_bytes(4, byteorder = 'big', signed = False)
		return t


	def fromDatetime(dt):
		t = (dt - NTPEpoch).total_seconds()
		frac, tot = math.modf(t)
		s = NTPTimeStamp()
		s.Seconds = int(tot)
		fs, ts = math.modf(frac*(2**32))
		s.Fraction = int(ts)
		return s

	def total(self):
		return float(self.Seconds) + float(self.Fraction / 2**32 )

	def toDatetime(self):
		return NTPEpoch + datetime.timedelta(seconds = self.Seconds, microseconds = self.Fraction/1000000)

class NTPPacket():
	def __init__(self, protocolType = NTPProtocolType.UDP, ipType = ipaddress.IPv4Address('0.0.0.0')):
		self.protocolType = protocolType
		self.ipType = ipType
		self.LI = None
		self.VN = None
		self.Mode = None
		self.Stratum = None
		self.Poll = None
		self.Precision = None
		self.RootDelay = None
		self.RootDispersion = None
		self.ReferenceID = None
		self.ReferenceTimestamp = None
		self.OriginTimestamp = None
		self.ReceiveTimestamp = None
		self.TransmitTimestamp = None
		self.ExtensionFields = None
		self.KeyIdentifier = None
		self.digest = None
		
	async def from_streamreader(reader):
		data = await reader.read()
		return NTPPacket.from_bytes(data)

	def from_bytes(bbuff, protocolType = NTPProtocolType.UDP):
		return NTPPacket.from_buffer(io.BytesIO(bbuff), protocolType)
	
	def from_buffer(buff, protocolType = NTPProtocolType.UDP):
		ntp = NTPPacket(protocolType)
		t = int.from_bytes(buff.read(1), byteorder='big', signed = False)
		ntp.LI = NTPLeapIndicator((t & 0xc0) >> 6)
		ntp.VN = (t & 0x38) >> 3
		ntp.Mode = NTPMode((t & 0x7))
		ntp.Stratum = NTPStratum( int.from_bytes(buff.read(1), byteorder='big', signed = False))
		ntp.Poll = 2**(int.from_bytes(buff.read(1), byteorder='big', signed = True)) 
		ntp.Precision = 2**(int.from_bytes(buff.read(1), byteorder='big', signed = True)) 
		ntp.RootDelay = NTPShort.from_buffer(buff)
		ntp.RootDispersion = NTPShort.from_buffer(buff)
		if ntp.Stratum == NTPStratum.UNSPECIFIED:
			ntp.ReferenceID = buff.read(4).decode()
		elif ntp.Stratum == NTPStratum.PRIMARY_SERVER:
			ntp.ReferenceID = buff.read(4).decode()
		elif ntp.Stratum.value in range(2,16):
			if isinstance(ntp.ipType, ipaddress.IPv4Address):
				ntp.ReferenceID = ipaddress.IPv4Address(buff.read(4))
			else:
				#this case it's IPv6, but since IPv6 bytes are larger
				#the standard comes up with MD5(IPv6)[:4]
				ntp.ReferenceID = buff.read(4)
		else:
			ntp.ReferenceID = buff.read(4)


		ntp.ReferenceTimestamp = NTPTimeStamp.from_buffer(buff)
		ntp.OriginTimestamp = NTPTimeStamp.from_buffer(buff)
		ntp.ReceiveTimestamp = NTPTimeStamp.from_buffer(buff)
		ntp.TransmitTimestamp = NTPTimeStamp.from_buffer(buff)
		#extensions here!
		#self.KeyIdentifier = buff.read(4)
		#self.digest = buff.read(4)

		return ntp

	def construct_fake_reply(originTS, dt, ip, protocolType = NTPProtocolType.UDP):
		ntp = NTPPacket(protocolType)
		ntp.LI = NTPLeapIndicator.NO_WARNING
		ntp.VN = 4
		ntp.Mode = NTPMode.SERVER
		ntp.Stratum = NTPStratum.SECONDARY_SERVER
		ntp.Poll = 4
		ntp.Precision = 0.00000001
		ntp.RootDelay = NTPShort.from_float(random.uniform(0.0200, 0.0100))
		ntp.RootDispersion = NTPShort.from_float(random.uniform(0.0500, 0.0100))
		ntp.ReferenceID = ip
		ntp.ReferenceTimestamp = NTPTimeStamp.fromDatetime(dt)
		ntp.OriginTimestamp = originTS
		ntp.ReceiveTimestamp = NTPTimeStamp.fromDatetime(dt)
		ntp.TransmitTimestamp = NTPTimeStamp.fromDatetime(dt)

		return ntp

	def to_bytes(self):
		temp  = self.LI.value << 6
		temp |= self.VN << 3
		temp |= self.Mode.value

		t  = temp.to_bytes(1, byteorder = 'big', signed = False)
		t += self.Stratum.value.to_bytes(1, byteorder = 'big', signed = False)
		t += int(math.log2(self.Poll)).to_bytes(1, byteorder = 'big', signed = True)
		t += int(math.log2(self.Precision)).to_bytes(1, byteorder = 'big', signed = True)
		t += self.RootDelay.to_bytes()
		t += self.RootDispersion.to_bytes()
		
		if self.Stratum == NTPStratum.UNSPECIFIED:
			t += self.ReferenceID.encode()
		elif self.Stratum == NTPStratum.PRIMARY_SERVER:
			t += self.ReferenceID.encode()
		elif self.Stratum.value in range(2,16):
			if isinstance(self.ipType, ipaddress.IPv4Address):
				t += self.ReferenceID.packed
			else:
				t += self.ReferenceID 
		else:
			t += self.ReferenceID 

		t += self.ReferenceTimestamp.to_bytes()
		t += self.OriginTimestamp.to_bytes()
		t += self.ReceiveTimestamp.to_bytes()
		t += self.TransmitTimestamp.to_bytes()

		return t

	def __repr__(self):
		t  = '== NTP Packet ==\r\n'
		t += 'LI : %s\r\n' % repr(self.LI)
		t += 'VN : %d\r\n' % self.VN
		t += 'Mode : %s\r\n' % repr(self.Mode)
		t += 'Stratum : %s\r\n' % repr(self.Stratum)
		t += 'Poll : %f\r\n' % self.Poll
		t += 'Precision : %f\r\n' % self.Precision
		t += 'RootDelay : %s\r\n' % str(self.RootDelay.total())
		t += 'RootDispersion : %s\r\n' % str(self.RootDispersion.total())
		if self.Stratum == NTPStratum.PRIMARY_SERVER:
			t += NTPStratumReferenceClock[self.ReferenceID.strip()]
		else:
			t += 'ReferenceID : %s\r\n' % repr(self.ReferenceID)
		t += 'ReferenceTimestamp : %s\r\n' % self.ReferenceTimestamp.toDatetime().isoformat()
		t += 'OriginTimestamp : %s\r\n' % self.OriginTimestamp.toDatetime().isoformat()
		t += 'ReceiveTimestamp : %s\r\n' % self.ReceiveTimestamp.toDatetime().isoformat()
		t += 'TransmitTimestamp : %s\r\n' % self.TransmitTimestamp.toDatetime().isoformat()

		return t
