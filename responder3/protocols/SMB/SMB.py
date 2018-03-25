import io
import enum
import binascii
import sys
from responder3.protocols.SMB.ntstatus import *
from responder3.protocols.SMB.utils import *

#https://msdn.microsoft.com/en-us/library/ee441774.aspx
class SMBHeader():
	def __init__(self):
		self.Protocol = None
		self.Command  = None
		self.Status   = None
		self.Flags    = None
		self.Flags2   = None
		self.PIDHigh  = None
		self.SecurityFeatures = None
		self.Signature = None
		self.Reserved = None
		self.TID      = None
		self.PIDLow   = None
		self.UID      = None
		self.MID      = None

	def from_bytes(bbuff):
		return SMBHeader.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		hdr = SMBHeader()
		hdr.Protocol = buff.read(4)
		assert hdr.Protocol == b'\xFFSMB', "SMBv1 Header Magic incorrect!"
		hdr.Command  = SMBCommand(int.from_bytes(buff.read(1), byteorder='little', signed = False))
		hdr.Status   = NTStatus(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		hdr.Flags    = SMBHeaderFlagsEnum(int.from_bytes(buff.read(1), byteorder='little', signed = False))
		hdr.Flags2   = SMBHeaderFlags2Enum(int.from_bytes(buff.read(2), byteorder='little', signed = False))
		hdr.PIDHigh  = int.from_bytes(buff.read(2), byteorder='little', signed = False)

		if SMBHeaderFlags2Enum.SMB_FLAGS2_SMB_SECURITY_SIGNATURE in hdr.Flags2:
			hdr.SecurityFeatures = buff.read(8)
		else:
			hdr.Signature = buff.read(8)

		hdr.Reserved = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.TID      = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.PIDLow   = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.UID      = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		hdr.MID      = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		return hdr

	def construct(command, status, flags, flags2, uid = 0, mid = 0, tid = 0, securityfeatures = None, signature = None, pidhigh = 0, pidlow = 0):
		hdr = SMBHeader()
		hdr.Protocol = b'\xFFSMB'
		hdr.Command  = command
		hdr.Status   = status
		hdr.Flags    = flags
		hdr.Flags2   = flags2
		hdr.PIDHigh  = pidhigh

		if SMBHeaderFlags2Enum.SMB_FLAGS2_SMB_SECURITY_SIGNATURE in hdr.Flags2:
			if securityfeatures is None:
				raise Exception('SMB_FLAGS2_SMB_SECURITY_SIGNATURE is present but SecurityFeatures was not supplied!')
			hdr.SecurityFeatures = securityfeatures
		else:
			if signature is not None:
				hdr.Signature = signature

		hdr.Reserved = 0
		hdr.TID      = tid
		hdr.PIDLow   = pidlow
		hdr.UID      = uid
		hdr.MID      = mid

		return hdr

	def toBytes(self):
		t  = self.Protocol
		t += self.Command.value.to_bytes(1, byteorder = 'little', signed=False)
		t += self.Status.value.to_bytes(4, byteorder = 'little', signed=False)
		t += self.Flags.to_bytes(1, byteorder = 'little', signed=False)
		t += self.Flags2.value.to_bytes(2, byteorder = 'little', signed=False)
		t += self.PIDHigh.to_bytes(2, byteorder = 'little', signed=False)
		if self.SecurityFeatures is not None:
			t += self.SecurityFeatures
		elif self.Signature is not None:
			t += self.Signature
		else:
			t += b'\x00'*8
		t += self.Reserved.to_bytes(2, byteorder = 'little', signed=False)
		t += self.TID.to_bytes(2, byteorder = 'little', signed=False)
		t += self.PIDLow.to_bytes(2, byteorder = 'little', signed=False)
		t += self.UID.to_bytes(2, byteorder = 'little', signed=False)
		t += self.MID.to_bytes(2, byteorder = 'little', signed=False)
		return t

	def __repr__(self):
		t = '===SMBHeader===\r\n'
		t += 'Command: %s\r\n' % self.Command.name
		t += 'Flags:   %s\r\n' % repr(self.Flags)
		t += 'Flags2:  %s\r\n' % repr(self.Flags2)
		t += 'PIDHigh: %d\r\n' % self.PIDHigh
		t += 'SecurityFeatures: %s\r\n' % (self.SecurityFeatures.hex() if self.SecurityFeatures is not None else 'NONE')
		t += 'Reserved: %d\r\n' % self.Reserved
		t += 'TID: %d\r\n' % self.TID
		t += 'PIDLow: %d\r\n' % self.PIDLow
		t += 'UID: %d\r\n' % self.UID
		t += 'MID: %d\r\n' % self.MID
		return t

#https://msdn.microsoft.com/en-us/library/ee441946.aspx
class SMB_COM_NEGOTIATE_REPLY():
	def __init__(self):
		##### SMB_Parameters #####
		self.WordCount = None
		self.DialectIndex = None #this is for really really old protocol dialects
		self.SecurityMode  = None
		self.MaxMpxCount   = None
		self.MaxNumberVcs  = None
		self.MaxBufferSize = None
		self.MaxRawSize    = None
		self.SessionKey    = None
		self.Capabilities  = None
		self.SystemTime    = None
		self.ServerTimeZone = None
		self.ChallengeLength= None
		##### SMB_Data #####
		self.ByteCount  = None
		self.Challenge  = None
		self.DomainName = None

		self.uuid = None
		self.secblob = None
		

	def from_bytes(bbuff):
		return SMB_COM_NEGOTIATE_REPLY.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		msg = SMB_COM_NEGOTIATE_REPLY()
		msg.WordCount       = int.from_bytes(buff.read(1), byteorder='little', signed = False)
		msg.DialectIndex    = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		msg.SecurityMode    = SMBSecurityMode(buff.read(1))
		msg.MaxMpxCount     = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		msg.MaxNumberVcs    = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		msg.MaxBufferSize   = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.MaxRawSize      = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.SessionKey      = buff.read(4)

		msg.Capabilities    = SMBCapabilities(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		msg.SystemTime      = wintime2datetime(int.from_bytes(buff.read(8), byteorder='little', signed = False))
		msg.ServerTimeZone  = int.from_bytes(buff.read(2), byteorder='little', signed = True)
		msg.ChallengeLength = int.from_bytes(buff.read(1), byteorder='little', signed = False)

		msg.ByteCount       = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		msg.Challenge       = buff.read(msg.ChallengeLength)
		msg.DomainName      = buff.read().deocde()
		return msg

	def construct(dialectindex, securitymode, sessionkey, capabilities, uuid, secblob, systemtime = datetime.datetime.utcnow()):
		msg = SMB_COM_NEGOTIATE_REPLY()
		msg.WordCount       = 0x11
		msg.DialectIndex    = dialectindex
		msg.SecurityMode    = securitymode
		msg.MaxMpxCount     = 50
		msg.MaxNumberVcs    = 1
		msg.MaxBufferSize   = 16644
		msg.MaxRawSize      = 65536
		msg.SessionKey      = sessionkey

		msg.Capabilities    = capabilities
		msg.SystemTime      = systemtime
		msg.ServerTimeZone  = 0
		msg.ChallengeLength = 0

		msg.ByteCount       = len(uuid.bytes_le) + len(secblob)
		msg.uuid = uuid
		msg.secblob = secblob

		return msg

	def toBytes(self):
		t  = b''
		t += self.WordCount.to_bytes(1, byteorder = 'little', signed=False)
		t += self.DialectIndex.to_bytes(2, byteorder = 'little', signed=False)
		t += self.SecurityMode.value.to_bytes(1, byteorder = 'little', signed=False)
		t += self.MaxMpxCount.to_bytes(2, byteorder = 'little', signed=False)
		t += self.MaxNumberVcs.to_bytes(2, byteorder = 'little', signed=False)
		t += self.MaxBufferSize.to_bytes(4, byteorder = 'little', signed=False)
		t += self.MaxRawSize.to_bytes(4, byteorder = 'little', signed=False)
		t += self.SessionKey
		t += self.Capabilities.to_bytes(4, byteorder = 'little', signed=False)
		t += dt2wt(self.SystemTime).to_bytes(8, byteorder = 'little', signed=False)
		t += self.ServerTimeZone.to_bytes(2, byteorder = 'little', signed=True)
		t += self.ChallengeLength.to_bytes(1, byteorder = 'little', signed=False)
		t += self.ByteCount.to_bytes(2, byteorder = 'little', signed=False)
		t += self.uuid.bytes_le
		t += self.secblob

		return t


	def __repr__(self):
		t = '=== SMB_COM_NEGOTIATE_REPLY ===\r\n'
		t += 'WordCount:     %d\r\n' % self.WordCount
		t += 'DialectIndex:  %d\r\n' % self.DialectIndex
		t += 'SecurityMode:  %s\r\n' % repr(self.SecurityMode)
		t += 'MaxMpxCount:   %d\r\n' % self.MaxMpxCount
		t += 'MaxNumberVcs:  %d\r\n' % self.MaxNumberVcs
		t += 'MaxBufferSize: %d\r\n' % self.MaxBufferSize
		t += 'MaxRawSize:    %d\r\n' % self.MaxRawSize
		t += 'SessionKey:    %s\r\n' % self.SessionKey.hex()
		t += 'Capabilities:  %s\r\n' % repr(self.Capabilities)
		t += 'SystemTime:    %s\r\n' % self.SystemTime.isoformat()
		t += 'ServerTimeZone:    %s\r\n' % self.ServerTimeZone
		t += 'ChallengeLength:    %d\r\n' % self.ChallengeLength

		return t

#https://msdn.microsoft.com/en-us/library/ee441913.aspx
class SMB_COM_NEGOTIATE_REQ():
	def __init__(self):
		##### parameters ####
		self.WordCount = None
		##### SMB_Data ###
		self.ByteCount = None
		self.Dialects  = None

	def from_bytes(bbuff):
		return SMB_COM_NEGOTIATE_REQ.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		cmd = SMB_COM_NEGOTIATE_REQ()
		cmd.WordCount = int.from_bytes(buff.read(1), byteorder='little', signed = False)
		if cmd.WordCount > 0:
			cmd.DialectIndex = []
			for i in range(cmd.WordCount):
				cmd.DialectIndex.append(int.from_bytes(buff.read(1), byteorder='little', signed = False))
		cmd.ByteCount = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.Dialects  = []
		for raw in buff.read(cmd.ByteCount).split(b'\x00'):
			if raw == b'':
				continue
			cmd.Dialects.append(SMB_Dialect(raw))
		return cmd

	def __repr__(self):
		t = '===SMB_COM_NEGOTIATE_REQ===\r\n'
		t += repr(self.params)
		t += repr(self.data)	
		return t

#https://msdn.microsoft.com/en-us/library/ee441849.aspx
class SMB_COM_SESSION_SETUP_ANDX_REQ():
	def __init__(self):
		##### parameters ####
		self.WordCount     = None
		self.AndXCommand   = None
		self.AndXReserved  = None
		self.AndXOffset    = None
		self.MaxBufferSize = None
		self.MaxMpxCount   = None
		self.VcNumber      = None
		self.SessionKey    = None
		self.SecurityBlobLen = None
		self.Reserved      = None
		self.Capabilities  = None
		##### SMB_Data ###
		self.ByteCount     = None
		self.SecurityBlob  = None
		self.NativeOS      = None
		self.NativeLanMan  = None

	def from_bytes(bbuff):
		return SMB_COM_SESSION_SETUP_ANDX_REQ.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		cmd = SMB_COM_SESSION_SETUP_ANDX_REQ()
		cmd.WordCount     = int.from_bytes(buff.read(1), byteorder='little', signed = False)
		cmd.AndXCommand   = int.from_bytes(buff.read(1), byteorder='little', signed = False)
		cmd.AndXReserved  = int.from_bytes(buff.read(1), byteorder='little', signed = False)
		cmd.AndXOffset    = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.MaxBufferSize = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.MaxMpxCount   = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.VcNumber      = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.SessionKey    = buff.read(4)
		cmd.SecurityBlobLen = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.Reserved      = buff.read(4)
		cmd.Capabilities  = SMBCapabilities(int.from_bytes(buff.read(4), byteorder='little', signed = False))
		cmd.ByteCount     = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.SecurityBlob  = buff.read(cmd.SecurityBlobLen)
		#be careful of padding at this point, a padding byte of \x00 might be inserted to keep the strings on a 16 byte alignment
		pos = buff.tell()
		if pos %2 != 0:
			buff.read(1)

		#this parsing is disgusting, but i have no better idea...
		t =  buff.read()
		print(t)
		print(t.decode('utf-16-le'))
		print(t.split(b'\x00\x00\x00'))
		t1, t2, *aaa = t.split(b'\x00\x00\x00')
		cmd.NativeOS      = (t1+b'\x00').decode('utf-16-le')
		cmd.NativeLanMan  = (t2+b'\x00').decode('utf-16-le')

		return cmd


	def __repr__(self):
		t = '===SMB_COM_SESSION_SETUP_AND_X_REQ===\r\n'
		t += repr(self.params)
		t += repr(self.data)	
		return t

#https://msdn.microsoft.com/en-us/library/ee442143.aspx
class SMB_COM_SESSION_SETUP_ANDX_REPLY():
	def __init__(self):
		##### parameters ####
		self.WordCount     = None
		self.AndXCommand   = None
		self.AndXReserved  = None
		self.AndXOffset    = None
		self.Action        = None
		self.SecurityBlobLen = None
		##### SMB_Data ###
		self.ByteCount     = None
		self.SecurityBlob  = None
		self.NativeOS      = None
		self.NativeLanMan  = None

	def from_bytes(bbuff):
		return SMB_COM_SESSION_SETUP_ANDX_REPLY.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		cmd = SMB_COM_SESSION_SETUP_ANDX_REPLY()
		cmd.WordCount     = int.from_bytes(buff.read(1), byteorder='little', signed = False)
		cmd.AndXCommand   = int.from_bytes(buff.read(1), byteorder='little', signed = False)
		cmd.AndXReserved  = int.from_bytes(buff.read(1), byteorder='little', signed = False)
		cmd.AndXOffset    = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.Action        = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.SecurityBlobLen = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.ByteCount     = int.from_bytes(buff.read(2), byteorder='little', signed = False)
		cmd.SecurityBlob  = buff.read(cmd.SecurityBlobLen)
		#be careful of padding at this point, a padding byte of \x00 might be inserted to keep the strings on a 16 byte alignment
		pos = buff.tell()
		if pos %2 != 0:
			buff.read(1)

		#this parsing is disgusting, but i have no better idea...
		t =  buff.read()
		t1, t2, *aaa = t.split(b'\x00\x00\x00')
		cmd.NativeOS      = t1.decode('utf16-le')
		cmd.NativeLanMan  = t2.decode('utf16-le')

		return cmd

	def construct(secblob = None, nativeos = None, nativelanman = None):
		cmd = SMB_COM_SESSION_SETUP_ANDX_REPLY()
		cmd.WordCount     = 4
		cmd.AndXCommand   = 0xff
		cmd.AndXReserved  = 0
		cmd.AndXOffset    = 0
		cmd.Action        = 0
		cmd.SecurityBlobLen = len(secblob)
		cmd.ByteCount     = None #to be set when toBytes is invoked
		cmd.SecurityBlob  = secblob
		cmd.NativeOS      = nativeos
		cmd.NativeLanMan  = nativelanman
		return cmd

	def toBytes(self):
		t  = self.WordCount.to_bytes(1, byteorder = 'little', signed=False)
		t += self.AndXCommand.to_bytes(1, byteorder = 'little', signed=False)
		t += self.AndXReserved.to_bytes(1, byteorder = 'little', signed=False)
		t += self.AndXOffset.to_bytes(2, byteorder = 'little', signed=False)
		t += self.Action.to_bytes(2, byteorder = 'little', signed=False)
		t += self.SecurityBlobLen.to_bytes(2, byteorder = 'little', signed=False)

		if self.NativeOS is None:
			nativeos = b''
		else:
			nativeos = (self.NativeOS + '\x00').encode('utf-16-le')
		
		if self.NativeLanMan is None:
			nativelanman = b''
		else:
			nativelanman = (self.NativeLanMan + '\x00').encode('utf-16-le')
		tlen = 2 + self.SecurityBlobLen + len(t)
		padneeded = tlen %2 != 0

		if padneeded:
			tlen += 1

		t += tlen.to_bytes(2, byteorder = 'little', signed=False) #this is he bytecount
		t += self.SecurityBlob
		if padneeded:
			t += b'\x00'
		t += nativeos
		t += nativelanman

		return t



	def __repr__(self):
		t = '===SMB_COM_SESSION_SETUP_ANDX_REPLY===\r\n'
		t += repr(self.params)
		t += repr(self.data)	
		return t

class SMBSetupAction(enum.Enum):
	SMB_SETUP_GUEST = 0x0001
	SMB_SETUP_USE_LANMAN_KEY = 0x0002

#https://msdn.microsoft.com/en-us/library/ee441616.aspx
class SMBCommand(enum.Enum): #SMB_COM
	SMB_COM_CREATE_DIRECTORY = 0x00
	SMB_COM_DELETE_DIRECTORY = 0x01
	SMB_COM_OPEN = 0x02
	SMB_COM_CREATE  = 0x03
	SMB_COM_CLOSE = 0x04
	SMB_COM_FLUSH = 0x05
	SMB_COM_DELETE = 0x06
	SMB_COM_RENAME = 0x07
	SMB_COM_QUERY_INFORMATION = 0x08
	SMB_COM_SET_INFORMATION = 0x09
	SMB_COM_READ = 0x0A
	SMB_COM_WRITE = 0x0B
	SMB_COM_LOCK_BYTE_RANGE = 0x0C
	SMB_COM_UNLOCK_BYTE_RANGE = 0x0D
	SMB_COM_CREATE_TEMPORARY = 0x0E
	SMB_COM_CREATE_NEW = 0x0F
	SMB_COM_CHECK_DIRECTORY = 0x10
	SMB_COM_PROCESS_EXIT = 0x11
	SMB_COM_SEEK = 0x12
	SMB_COM_LOCK_AND_READ = 0x13
	SMB_COM_WRITE_AND_UNLOCK = 0x14
	#Unused 0x15-0x19
	SMB_COM_READ_RAW = 0x1A
	SMB_COM_READ_MPX = 0x1B
	SMB_COM_READ_MPX_SECONDARY = 0x1C
	SMB_COM_WRITE_RAW = 0x1D
	SMB_COM_WRITE_MPX = 0x1E
	SMB_COM_WRITE_MPX_SECONDARY = 0x1F
	SMB_COM_WRITE_COMPLETE = 0x20
	SMB_COM_QUERY_SERVER  = 0x21
	SMB_COM_SET_INFORMATION2 = 0x22
	##### TODODODODODODODO!!!!!!!!!!!!!!!!!
	SMB_COM_NEGOTIATE = 0x72
	SMB_COM_SESSION_SETUP_ANDX = 0x73
	SMB_COM_LOGOFF_ANDX = 0x74
	SMB_COM_TREE_CONNECT_ANDX = 0x75

class SMBHeaderFlagsEnum(enum.IntFlag):
	SMB_FLAGS_LOCK_AND_READ_OK = 0x01
	SMB_FLAGS_BUF_AVAIL = 0x02
	Reserved = 0x04
	SMB_FLAGS_CASE_INSENSITIVE = 0x08
	SMB_FLAGS_CANONICALIZED_PATHS = 0x10
	SMB_FLAGS_OPLOCK = 0x20
	SMB_FLAGS_OPBATCH = 0x40
	SMB_FLAGS_REPLY = 0x80

class SMBHeaderFlags2Enum(enum.IntFlag):
	SMB_FLAGS2_LONG_NAMES = 0x0001
	SMB_FLAGS2_EAS = 0x0002
	SMB_FLAGS2_SMB_SECURITY_SIGNATURE = 0x0004
	SMB_FLAGS2_IS_LONG_NAME = 0x0040
	SMB_FLAGS2_EXTENDED_SECURITY = 0x0800
	SMB_FLAGS2_DFS = 0x1000
	SMB_FLAGS2_PAGING_IO = 0x2000
	SMB_FLAGS2_NT_STATUS = 0x4000
	SMB_FLAGS2_UNICODE = 0x8000

class SMBSecurityMode(enum.IntFlag):
	NEGOTIATE_USER_SECURITY = 0x01
	NEGOTIATE_ENCRYPT_PASSWORDS = 0x02
	NEGOTIATE_SECURITY_SIGNATURES_ENABLED = 0x04
	NEGOTIATE_SECURITY_SIGNATURES_REQUIRED = 0x08
	#others are Reserved

class SMBCapabilities(enum.IntFlag):
	CAP_RAW_MODE         = 0x00000001
	CAP_MPX_MODE         = 0x00000002
	CAP_UNICODE          = 0x00000004
	CAP_LARGE_FILES      = 0x00000008
	CAP_NT_SMBS          = 0x00000010
	CAP_RPC_REMOTE_APIS  = 0x00000020
	CAP_STATUS32         = 0x00000040
	CAP_LEVEL_II_OPLOCKS = 0x00000080
	CAP_LOCK_AND_READ    = 0x00000100
	CAP_NT_FIND          = 0x00000200
	CAP_BULK_TRANSFER    = 0x00000400
	CAP_COMPRESSED_DATA  = 0x00000800
	CAP_DFS              = 0x00001000
	CAP_QUADWORD_ALIGNED = 0x00002000
	CAP_LARGE_READX      = 0x00004000
	CAP_NT_EXTENDED_SECURITY = 0x80000000

class SMB_Dialect():
	def __init__(self, data = None):
		self.BufferFormat = None
		self.DialectString = None

		if data is not None:
			self.parse(data)

	""" TODO!!!
	def from_bytes(bbuff):
		return SMB_Dialect.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		cmd = SMB_Dialect()
		cmd.BufferFormat  = buff.read(1)
		cmd.DialectString = SMB_COM_NEGOTIATE_REQ_DATA.from_buffer(buff)
		return cmd
	"""
	def parse(self, data):
		self.BufferFormat  = data[0]
		self.DialectString = data[1:].decode('ascii')

	def __repr__(self):
		t = ''
		t += 'DialectString: %s' % self.DialectString
		return t

class SMBMessage():
	def __init__(self):
		self.type      = 1
		self.header    = None
		self.command   = None

	def from_bytes(bbuff):
		return SMBMessage.from_buffer(io.BytesIO(bbuff))

	def from_buffer(buff):
		msg = SMBMessage()
		msg.header = SMBHeader.from_buffer(buff)
		classname = msg.header.Command.name
		if SMBHeaderFlagsEnum.SMB_FLAGS_REPLY in msg.header.Flags:
			classname += '_REPLY'
		else:
			classname += '_REQ'
		class_ = getattr(sys.modules[__name__], classname)
		msg.command = class_.from_buffer(buff)
		
		return msg

	def toBytes(self):
		t  = self.header.toBytes()
		t += self.command.toBytes() 
		return t

	def __repr__(self):
		t = '== SMBMessage ==\r\n'
		t += repr(self.header)
		t += repr(self.command)
		return t
