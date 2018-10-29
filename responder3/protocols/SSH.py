#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

# https://tools.ietf.org/html/rfc4511
# https://msdn.microsoft.com/en-us/library/cc223501.aspx
# https://ldap3.readthedocs.io/bind.html

from asn1crypto import core
import enum
import os
import io

from responder3.core.commons import *
from responder3.core.asyncio_helpers import *
import hashlib

MAX_PACKET_LENGTH = 35000

class MPInt:
	def __init__(self):
		pass
		
	@staticmethod
	def from_buff(buff):
		length = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		if length == 0:
			return None
		data = buff.read(length)
		return int.from_bytes(data, byteorder = 'big', signed = False)
		
	@staticmethod
	def to_bytes(i):
		if not i:
			return b''
		
		li = int((i.bit_length() + 7) /8 ) 
		length = i.to_bytes(li, byteorder="big", signed = False)
		return length + data

class NameList:
	def __init__(self):
		pass
		
	@staticmethod
	def from_buff(buff):
		length = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		if length == 0:
			return []
		data = buff.read(length).decode()
		return data.split(',')
		
	@staticmethod
	def to_bytes(lst):
		if len(lst) == 0:
			return len(lst).to_bytes(4, byteorder="big", signed = False)
		data = ','.join(lst)
		data = data.encode()
		length = len(data).to_bytes(4, byteorder="big", signed = False)
		return length + data
	
	
class SSHMessageNumber(enum.Enum):
	SSH_MSG_DISCONNECT = 1
	SSH_MSG_IGNORE=2
	SSH_MSG_UNIMPLEMENTED=3
	SSH_MSG_DEBUG=4
	SSH_MSG_SERVICE_REQUEST=5
	SSH_MSG_SERVICE_ACCEPT=6
	SSH_MSG_KEXINIT=20
	SSH_MSG_NEWKEYS=21
	
	SSH2_MSG_KEXDH_INIT = 30
	SSH2_MSG_KEXDH_REPLY = 31

class SSHPacket:
	def __init__(self):
		self.packet_length = None
		self.padding_length = None
		self.payload = None
		self.random_padding = None
		self.mac = None
		
	def to_bytes(self, cipher = None):
		if not cipher:
			payload = self.payload.to_bytes()
			random_padding = os.urandom(len(payload) % 8)
			mac = b''
			packet_length = len(payload) + len(random_padding)
			
			return packet_length.to_bytes(4, byteorder="big", signed = False) + len(random_padding).to_bytes(1, byteorder="big", signed = False) + payload + random_padding + mac
		
		
	def __repr__(self):
		return str(self)
	
	def __str__(self):
		t = ''
		t += 'length: %s\r\n' % self.packet_length
		t += 'padding length: %s\r\n' % self.padding_length
		t += 'payload: %s\r\n' % str(self.payload)
		t += 'random_padding: %s\r\n' % self.random_padding
		t += 'mac: %s\r\n' % self.mac
		return t
		
class SSH_MSG_KEXINIT:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH_MSG_KEXINIT
		self.cookie = None
		self.kex_algorithms = None
		self.server_host_key_algorithms = None
		self.encryption_algorithms_client_to_server = None
		self.encryption_algorithms_server_to_client = None
		self.mac_algorithms_client_to_server = None
		self.mac_algorithms_server_to_client = None
		self.compression_algorithms_client_to_server = None
		self.compression_algorithms_server_to_client = None
		self.languages_client_to_server = None
		self.languages_server_to_client = None
		self.first_kex_packet_follows = None
		self.dummy = 0
		
	@staticmethod
	def from_bytes(data):
		return SSH_MSG_KEXINIT.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_KEXINIT()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.cookie = buff.read(16)
		msg.kex_algorithms = NameList.from_buff(buff)
		msg.server_host_key_algorithms = NameList.from_buff(buff)
		msg.encryption_algorithms_client_to_server = NameList.from_buff(buff)
		msg.encryption_algorithms_server_to_client = NameList.from_buff(buff)
		msg.mac_algorithms_client_to_server = NameList.from_buff(buff)
		msg.mac_algorithms_server_to_client = NameList.from_buff(buff)
		msg.compression_algorithms_client_to_server = NameList.from_buff(buff)
		msg.compression_algorithms_server_to_client = NameList.from_buff(buff)
		msg.languages_client_to_server = NameList.from_buff(buff)
		msg.languages_server_to_client = NameList.from_buff(buff)
		msg.first_kex_packet_follows = bool(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		msg.dummy = int.from_bytes(buff.read(4), byteorder = 'big', signed = False) #should be 0
		return msg
		
	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.cookie
		data += NameList.to_bytes(self.kex_algorithms)
		data += NameList.to_bytes(self.server_host_key_algorithms)
		data += NameList.to_bytes(self.encryption_algorithms_client_to_server)
		data += NameList.to_bytes(self.encryption_algorithms_server_to_client)
		data += NameList.to_bytes(self.mac_algorithms_client_to_server)
		data += NameList.to_bytes(self.mac_algorithms_server_to_client)
		data += NameList.to_bytes(self.compression_algorithms_client_to_server)
		data += NameList.to_bytes(self.compression_algorithms_server_to_client)
		data += NameList.to_bytes(self.languages_client_to_server)
		data += NameList.to_bytes(self.languages_server_to_client)
		data += b'\x00' if not self.first_kex_packet_follows else b'\x01'
		data += self.dummy.to_bytes(4, byteorder = 'big', signed = False)

		return data
		
	def __str__(self):
		t = ''
		t += 'Packet type: %s\r\n' % self.packet_type.name
		t += 'cookie: %s\r\n' % self.cookie.hex()
		t += 'kex_algorithms: %s\r\n' % ','.join(self.kex_algorithms)
		t += 'server_host_key_algorithms: %s\r\n' % ','.join(self.server_host_key_algorithms)
		t += 'encryption_algorithms_client_to_server: %s\r\n' % ','.join(self.encryption_algorithms_client_to_server)
		t += 'encryption_algorithms_server_to_client: %s\r\n' % ','.join(self.encryption_algorithms_server_to_client)
		t += 'mac_algorithms_client_to_server: %s\r\n' % ','.join(self.mac_algorithms_client_to_server)
		t += 'mac_algorithms_server_to_client: %s\r\n' % ','.join(self.mac_algorithms_server_to_client)
		t += 'compression_algorithms_client_to_server: %s\r\n' % ','.join(self.compression_algorithms_client_to_server)
		t += 'compression_algorithms_server_to_client: %s\r\n' % ','.join(self.compression_algorithms_server_to_client)
		t += 'languages_client_to_server: %s\r\n' % ','.join(self.languages_client_to_server)
		t += 'languages_server_to_client: %s\r\n' % ','.join(self.languages_server_to_client)
		t += 'first_kex_packet_follows: %s\r\n' % str(self.first_kex_packet_follows)
		t += 'dummy: %s\r\n' % str(self.dummy)
		
		return t
		
class SSH2_MSG_KEXDH_INIT:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH2_MSG_KEXDH_INIT
		self.mpint = None
		
	@staticmethod
	def from_bytes(data):
		return SSH2_MSG_KEXDH_INIT.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		msg = SSH2_MSG_KEXDH_INIT()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.mpint = MPInt.from_buff(buff)
		return msg
		
	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += MPInt.to_bytes(self.mpint)
		return data
		
	def __str__(self):
		t = ''
		t += 'Packet type: %s\r\n' % self.packet_type.name
		t += 'mpint: %s\r\n' % self.mpint
		return t
		
		
class SSH2_MSG_KEXDH_REPLY:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH2_MSG_KEXDH_REPLY
		self.cookie = None
		

type2msg = {
	SSHMessageNumber.SSH_MSG_DISCONNECT : None, 
	SSHMessageNumber.SSH_MSG_IGNORE : None, 
	SSHMessageNumber.SSH_MSG_UNIMPLEMENTED : None, 
	SSHMessageNumber.SSH_MSG_DEBUG : None, 
	SSHMessageNumber.SSH_MSG_SERVICE_REQUEST : None, 
	SSHMessageNumber.SSH_MSG_SERVICE_ACCEPT : None, 
	SSHMessageNumber.SSH_MSG_KEXINIT : SSH_MSG_KEXINIT, 
	SSHMessageNumber.SSH_MSG_NEWKEYS : None,
	SSHMessageNumber.SSH2_MSG_KEXDH_INIT : SSH2_MSG_KEXDH_INIT,
	SSHMessageNumber.SSH2_MSG_KEXDH_REPLY : SSH2_MSG_KEXDH_REPLY,
}

dh_groups = {
	14: {
		"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
		"g": 2
	},
}

class DH:
	def __init__(self, group_no, privkey = None):
		self.p = dh_groups[group_no]['p']
		self.g = dh_groups[group_no]['g']
		
		self.privkey = int.from_bytes(os.urandom(32), byteorder = 'big', signed = False) if not privkey else privkey		
		self.shared_key = None
		
	def validate_remote_key(self, rkey):
		"""
		Only a sith deals in integers in crypto...
		"""
		if 2 <= rkey and rkey <= self.p - 2:
			if pow(rkey, (self.p - 1) // 2, self.p) == 1:
				return True
		return False
		
	def get_shared_key(self, rkey):
		if self.validate_remote_key(rkey) == False:
			raise Exception('Remote key invalid!')
			
		self.shared_key = pow(rkey, self.privkey, self.p)
		return hashlib.sha256(self.shared_key.to_bytes(256, byteorder = 'big', signed = False)).hexdigest()

class SSHCipher:
	def __init__(self):
		# banner and KEX messages can be hardcoded. pick diffie-hellman-group14-sha1, aes128-ctr, hmac-sha1 or sha256, no compression
		self.supported_kex_algorithms = ['diffie-hellman-group14-sha1']
		self.supported_server_host_key_algorithms = ['ssh-rsa']
		self.supported_encryption_algorithms = ['aes128-ctr']
		self.supported_mac_algorithms = ['hmac-sha1']
		self.supported_compression_algorithms = ['none']
		self.supported_languages = []
		
		#self.kex = None #this should be set automatically but currently we only use one
		self.kex = DH(14)
		self.server_cipher = None
		self.client_cipher = None
		
	def generate_server_key_rply(self):
		msg = SSH_MSG_KEXINIT()
		msg.cookie = os.urandom(16)
		msg.kex_algorithms = self.supported_kex_algorithms
		msg.server_host_key_algorithms = self.supported_server_host_key_algorithms
		msg.encryption_algorithms_client_to_server = self.supported_encryption_algorithms
		msg.encryption_algorithms_server_to_client = self.supported_encryption_algorithms
		msg.mac_algorithms_client_to_server = self.supported_mac_algorithms
		msg.mac_algorithms_server_to_client = self.supported_mac_algorithms
		msg.compression_algorithms_client_to_server = self.supported_compression_algorithms
		msg.compression_algorithms_server_to_client = self.supported_compression_algorithms
		msg.languages_client_to_server = self.supported_languages
		msg.languages_server_to_client = self.supported_languages
		msg.first_kex_packet_follows = False
		return msg
		
class SSHParser:
	def __init__(self):
		pass
	
	@staticmethod
	async def from_streamreader(reader, cipher = None):
		try:
			packet = SSHPacket()
			if not cipher:
				#packet is not encrypted at this point
				packet_length = await readexactly_or_exc(reader, 4)
				packet.packet_length = int.from_bytes(packet_length, byteorder = 'big', signed = False)
				if packet.packet_length > MAX_PACKET_LENGTH:
					raise Exception('SSH packet too large!')
					
				data = await readexactly_or_exc(reader, packet.packet_length)
				packet.padding_length = data[0]
				message_type = SSHMessageNumber(data[1])
				print(message_type)
				packet.payload = type2msg[message_type].from_bytes(data[1:(packet.packet_length - packet.padding_length - 1)])
				packet.random_padding = data[-packet.padding_length:]
				packet.mac = None
				return packet
		except Exception as e:
			print(e)
			
		
		