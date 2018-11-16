#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#



from asn1crypto import core
import enum
import os
import io

from responder3.core.commons import *
from responder3.core.asyncio_helpers import *
from responder3.crypto.pure.AES.AES import Counter, AESModeOfOperationCTR

import hashlib
import struct
import rsa
from rsa import pkcs1
import hmac

MAX_PACKET_LENGTH = 35000
zero_byte = b'\x00'


class SSHPrivKey:
	name = 'ssh-rsa'
	def __init__(self, privkey = None):
		self.privkey = privkey
	
	@staticmethod
	def load_privkey_from_string(pk_str):
		"""
		Loads a PEM encoded RSA private key
		Format must be the same as /etc/ssh/ssh_host_rsa_key
		(openssl RSA private key)
		"""
		pk = SSHPrivKey()
		pk.privkey = rsa.PrivateKey.load_pkcs1(pk_str,'PEM')
		return pk
		
	@staticmethod
	def load_privkey_from_file(filename):
		with open(filename, 'rb') as f:
			return SSHPrivKey.load_privkey_from_string(f.read())
		
		
	def sign(self, data):
		"""
		hashes the data with sha1 and signs the result using pkcs1.5 and SHA-1
		returns bytes
		data must be bytes!
		"""
		return pkcs1.sign(data, self.privkey, 'SHA-1')


class SSHstring:
	def __init__(self):
		pass
		
	@staticmethod
	def from_buff(buff):
		length = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		if length == 0:
			return None
		data = buff.read(length)
		return data.decode()
		
	@staticmethod
	def to_bytes(s):
		if not s:
			return b''
		
		data = s.encode()
		length = len(data).to_bytes(4, byteorder="big", signed = False)
		return length + data
		
class SSHBytes:
	@staticmethod
	def from_buff(buff):
		length = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		if length == 0:
			return None
		return buff.read(length)
		
	@staticmethod
	def to_bytes(s):
		if not s:
			data = b''
			return len(data).to_bytes(4, byteorder="big", signed = False)
		
		length = len(s).to_bytes(4, byteorder="big", signed = False)
		return length + s
		
class MPInt:
	"""
	THIS CLASS IS ONLY FOR POSITIVE INTEGERS!!!
	"""
	def __init__(self):
		pass
		
	@staticmethod
	def from_buff(buff):
		length = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		if length == 0:
			return None
		print('MPInt len : %s' % length)
		contents = buff.read()
		print('Contents: %s' % contents.hex())
		buff = io.BytesIO(contents)
		data = buff.read(length)
		print(length)
		print(data.hex())
		if data[0] == 0:
			data = data[1:]
		return MPInt.bytes2int(data)
		
	@staticmethod
	def to_bytes(integer):
		if integer is None:
			return b'\x00' * 4
		bdata = MPInt.int2bytes(integer)
		if bdata[0] > 128:
			bdata = b'\x00' + bdata
		return len(bdata).to_bytes(4, byteorder="big", signed = False) + bdata
		
	@staticmethod
	def int2bytes_padded(integer):
		bdata = MPInt.int2bytes(integer)
		if bdata[0] > 128:
			bdata = b'\x00' + bdata
		return bdata
		
	@staticmethod
	def bytes2int(s):
		return int.from_bytes(s, 'big', signed = False)
		
	@staticmethod
	def int2bytes(integer):
		"""
		Only for positive integers!
		"""
		hd = hex(integer)[2:]
		if len(hd) %2:
			hd = '0' + hd
		
		return bytes.fromhex(hd)
		#return integer.to_bytes((integer.bit_length() + 7) // 8, byteorder = 'big', signed = False)
	
		

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
	
	SSH_MSG_USERAUTH_REQUEST = 50
	SSH_MSG_USERAUTH_FAILURE = 51
	SSH_MSG_USERAUTH_SUCCESS = 52
	SSH_MSG_USERAUTH_BANNER = 53

class SSHPacket:
	def __init__(self):
		self.packet_length = None
		self.padding_length = None
		self.payload = None
		self.random_padding = None
		self.mac = None
		
	def to_bytes(self, cipher = None):
		if not cipher:
			align = 8
			payload = self.payload.to_bytes()
			padlen = 3 + align - ((len(payload) + 8) % align) #len(payload) + 1 + 4
			#nopad_size = 3 + align - ((len(payload) + 8) % align) #len(payload) + 1 + 4
			#padlen = align - divmod(nopad_size, align)[1]
			random_padding = os.urandom(padlen)
			packet_length = len(payload) + len(random_padding)  + 1
			
			return packet_length.to_bytes(4, byteorder="big", signed = False) + len(random_padding).to_bytes(1, byteorder="big", signed = False) + payload + random_padding
		
		
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
		
		self.raw = b'' #raw bytes of the message, will be used later for calculating keys
		
	@staticmethod
	def from_bytes(data):
		return SSH_MSG_KEXINIT.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_KEXINIT()
		
		msg.raw = buff.read()
		buff = io.BytesIO(msg.raw)
		
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

		self.raw = data
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
		self.e = None #https://tools.ietf.org/html/rfc4253 section 8

	@staticmethod
	def from_bytes(data):
		return SSH2_MSG_KEXDH_INIT.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		msg = SSH2_MSG_KEXDH_INIT()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.e = MPInt.from_buff(buff)
		return msg
		
	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += MPInt.to_bytes(self.e)
		return data
		
	def __str__(self):
		t = ''
		t += 'Packet type: %s\r\n' % self.packet_type.name
		t += 'e: %s\r\n' % self.e
		return t
		
class SSHRSACertData:
	def __init__(self):
		self.identifier = "ssh-rsa" #SSHstring
		self.e = None #mpint
		self.n = None #mpint
	
	@staticmethod
	def from_bytes(data):
		return SSHRSACertData.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		buff.read(4)
		msg = SSHRSACertData()
		msg.identifier = SSHstring.from_buff(buff)
		msg.e = MPInt.from_buff(buff)
		msg.n = MPInt.from_buff(buff)
		return msg
		
	def to_bytes(self):
		t = b''
		t += SSHstring.to_bytes(self.identifier)
		t += MPInt.to_bytes(self.e)
		t += MPInt.to_bytes(self.n)
		t = len(t).to_bytes(4, byteorder = 'big', signed = False) + t
		return t
		
	def __str__(self):
		t = 'SSHRSACertData\r\n'
		t += 'identifier: %s\r\n' % self.identifier
		t += 'e: %s\r\n' % self.e
		t += 'n: %s\r\n' % self.n
		return t

class SSHRSASignatureData:
	def __init__(self):
		self.identifier = "ssh-rsa" #SSHstring
		self.rsa_signature_blob = None #bytes of the result of the signing operation
	
	@staticmethod
	def from_bytes(data):
		return SSHRSASignatureData.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		buff.read(4)
		msg = SSHRSASignatureData()
		msg.identifier = SSHstring.from_buff(buff)
		msg.rsa_signature_blob = SSHBytes.from_buff(buff)
		return msg
		
	def to_bytes(self):
		t = b''
		t += SSHstring.to_bytes(self.identifier)
		t += SSHBytes.to_bytes(self.rsa_signature_blob)
		t = len(t).to_bytes(4, byteorder = 'big', signed = False) + t
		return t
		
	def __str__(self):
		t = 'SSHRSASignatureData\r\n'
		t += 'identifier: %s\r\n' % self.identifier
		t += 'rsa_signature_blob: %s\r\n' % self.rsa_signature_blob
		return t		

		
class SSHDSSCertData:
	def __init__(self):
		self.identifier = "ssh-dss" #SSHstring
		self.p = None #mpint
		self.q = None #mpint
		self.g = None #mpint
		self.y = None #mpint
	
	@staticmethod
	def from_bytes(data):
		return SSHDSSCertData.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		buff.read(4)
		msg = SSHDSSCertData()
		msg.identifier = SSHstring.from_buff(buff)
		self.p = MPInt.from_buff(buff)
		self.q = MPInt.from_buff(buff)
		self.g = MPInt.from_buff(buff)
		self.y = MPInt.from_buff(buff)
		t = len(t).to_bytes(4, byteorder = 'big', signed = False) + t
		return msg
		
	def to_bytes(self):
		t = b''
		t += SSHstring.to_bytes(self.identifier)
		t += MPInt.to_bytes(self.p)
		t += MPInt.to_bytes(self.q)
		t += MPInt.to_bytes(self.g)
		t += MPInt.to_bytes(self.y)
		return t
		
	def __str__(self):
		t = 'SSHDSSCertData\r\n'
		t += 'identifier: %s\r\n' % self.identifier
		t += 'p: %s\r\n' % self.p
		t += 'q: %s\r\n' % self.q
		t += 'g: %s\r\n' % self.g
		t += 'y: %s\r\n' % self.y
		return t
		

		
		
class SSH2_MSG_KEXDH_REPLY:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH2_MSG_KEXDH_REPLY
		self.pubkey_string = None
		self.f = None
		self.h_sig = None
		
	@staticmethod
	def from_bytes(data):
		return SSH2_MSG_KEXDH_REPLY.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buff):
		msg = SSH2_MSG_KEXDH_REPLY()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.pubkey_string = None
		msg.f = None
		msg.h_sig = None
		return msg
		
	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		data += self.pubkey_string.to_bytes()
		data += MPInt.to_bytes(self.f)
		data += self.h_sig.to_bytes()
		return data
		
	def __str__(self):
		t = ''
		t += 'Packet type: %s\r\n' % self.packet_type.name
		t += 'mpint: %s\r\n' % self.mpint
		return t
		
		
"""
byte      SSH_MSG_KEXDH_REPLY
      string    server public host key and certificates (K_S)
      mpint     f
      string    signature of H
"""
class SSH_MSG_NEWKEYS:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH_MSG_NEWKEYS

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_NEWKEYS.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_NEWKEYS()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		return msg

	def to_bytes(self):
		data = b''
		data += self.packet_type.value.to_bytes(1, byteorder = 'big', signed = False)
		return data

class SSH_MSG_SERVICE_REQUEST:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH_MSG_SERVICE_REQUEST
		self.service_name = None

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_SERVICE_REQUEST.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_SERVICE_REQUEST()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.service_name = SSHstring.from_buff(buff)
		return msg

class SSH_MSG_SERVICE_ACCEPT:
	def __init__(self):
		self.packet_type = SSHMessageNumber.SSH_MSG_SERVICE_ACCEPT
		self.service_name = None

	@staticmethod
	def from_bytes(data):
		return SSH_MSG_SERVICE_REQUEST.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		msg = SSH_MSG_SERVICE_REQUEST()
		msg.packet_type = SSHMessageNumber(buff.read(1)[0])
		msg.service_name = SSHstring.from_buff(buff)
		return msg

type2msg = {
	SSHMessageNumber.SSH_MSG_DISCONNECT : None, 
	SSHMessageNumber.SSH_MSG_IGNORE : None, 
	SSHMessageNumber.SSH_MSG_UNIMPLEMENTED : None, 
	SSHMessageNumber.SSH_MSG_DEBUG : None, 
	SSHMessageNumber.SSH_MSG_SERVICE_REQUEST : SSH_MSG_SERVICE_REQUEST, 
	SSHMessageNumber.SSH_MSG_SERVICE_ACCEPT : SSH_MSG_SERVICE_ACCEPT, 
	SSHMessageNumber.SSH_MSG_KEXINIT : SSH_MSG_KEXINIT, 
	SSHMessageNumber.SSH_MSG_NEWKEYS : SSH_MSG_NEWKEYS,
	SSHMessageNumber.SSH2_MSG_KEXDH_INIT : SSH2_MSG_KEXDH_INIT,
	SSHMessageNumber.SSH2_MSG_KEXDH_REPLY : SSH2_MSG_KEXDH_REPLY,
}

dh_groups = {
	# 2048-bit
	14: {
		"p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
		"g": 2, 
		"keysize" : 2048
	},
}

class DH:
	def __init__(self, group_no, privkey = None):
		self.p = dh_groups[group_no]['p']
		self.g = dh_groups[group_no]['g']
		self.keysize = int(dh_groups[group_no]['keysize'] / 8)
		
		maxin = (self.p - 1) // 2
		bs = len(maxin.to_bytes((maxin.bit_length() + 7) // 8, 'big'))
		self.y = int.from_bytes(os.urandom(bs), byteorder = 'big', signed = False) if not privkey else privkey		
		self.f = pow(self.g, self.y, self.p) # dh_server_pub
		self.shared_key = None
		
	def get_shared_key(self, e):
		if not (2 <= e and e <= self.p - 2):
			raise Exception('Remote key invalid!')
			
		print('DH e: %s' % e)
		print('DH y: %s' % self.y)
		print('DH p: %s' % self.p)
		
		self.shared_key = pow(e, self.y, self.p)
		return self.shared_key
		#return hashlib.sha256(self.shared_key.to_bytes(256, byteorder = 'big', signed = False)).hexdigest()
	
class SSHCipher:
	def __init__(self):	
		self.server_host_keys = {
			#SSHPrivKey.name : SSHPrivKey.load_privkey_from_file('C:\\Users\\windev\\Desktop\\Responder3\\responder3\\tools\\ssh_server_test_cert.priv')
			SSHPrivKey.name : SSHPrivKey.load_privkey_from_file('/home/responder/Desktop/Responder3/responder3/tools/ssh_server_test_cert.priv')
		}
		
		"""
		self.kex_algorithms = [
			
		]
		"""
	
		# banner and KEX messages can be hardcoded. pick diffie-hellman-group14-sha1, aes128-ctr, hmac-sha1 or sha256, no compression
		self.supported_kex_algorithms = ['diffie-hellman-group14-sha1']
		self.supported_server_host_key_algorithms = [x for x in self.server_host_keys]
		self.supported_encryption_algorithms = ['aes128-ctr']
		self.supported_mac_algorithms = ['hmac-sha1']
		self.supported_compression_algorithms = ['none']
		self.supported_languages = []
		
		self.selected_kex_algorithm = 'diffie-hellman-group14-sha1'
		self.selected_server_host_key_algorithm = 'ssh-rsa'
		self.selected_encryption_algorithm = 'aes128-ctr'
		self.selected_mac_algorithm = 'hmac-sha1'
		self.selected_compression_algorithm = None
		self.selected_language = None
		
		#self.server_rsa_key = 
		#self.server_dsa_key = None
		#self.server_key = None #this should be set via server starup config parameters
		#self.pubkey, self.privkey = rsa.newkeys(2048)
		#self.server_kex_assymmetric =   #this should be set automatically but currently we only use one
		
		#self.kex = None #this should be set automatically but currently we only use one
		self.kex = DH(14)
		self.server_cipher = None
		self.client_cipher = None
		self.server_hmac = None
		self.client_hmac = None
		
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
		
	
		

	def calculate_kex(self, client_id, server_id, client_kexinit_payload, server_kexinit_payload, client_msg):
		#currently only DH + RSA is supported!
		
		###### SHARED SECRET CALC
		if self.selected_kex_algorithm == 'diffie-hellman-group14-sha1':
			"""
			#parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
			# Generate a private key for use in the exchange.
			sc = pow(client_msg.e, self.kex.y, self.kex.p)
			K = MPInt.int2bytes(sc, False)
			self.kex_hash = hashlib.sha1
			
			#calculating client's secret key
			#sc = self.kex.get_shared_key(client_msg.e)
			#K =  MPInt.int2bytes(sc, False) #shared secret
			"""
			self.kex_hash = hashlib.sha1
			self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
			self.g = 2
			self.x = 31337
			self.f = pow(self.g, self.x, self.p)
			sc = pow(client_msg.e, self.x, self.p)
			K = MPInt.int2bytes(sc)
			
			
			print('Shared Secret -int-: %s' % sc)
			print('Shared Secret -bytes-: %s' % K.hex())
			
		
		else:
			raise Exception('Unsupported KEX algo!')
			
		if self.selected_server_host_key_algorithm == 'ssh-rsa':
			pkey = self.server_host_keys['ssh-rsa']
			print('Server host key "e" %s' % pkey.privkey.e)
			print('Server host key "N" %s' % pkey.privkey.n)
			server_host_key = SSHRSACertData()
			server_host_key.e = pkey.privkey.e
			server_host_key.n = pkey.privkey.n
		
		else:
			raise Exception('Server host key algo!')
		
		print('Client id: %s' % client_id)
		print('server_id: %s' % server_id)
		print('client_kexinit_payload: \r\n%s' % hexdump(client_kexinit_payload))
		print('server_kexinit_payload: \r\n%s' % hexdump(server_kexinit_payload))
		print('server_host_key:\r\n %s' % hexdump((server_host_key.to_bytes())))
		print('client_msg.e: %s' % MPInt.int2bytes(client_msg.e).hex())
		print('dh_server_pub: %s' % MPInt.int2bytes(self.f).hex())
		print('K: %s' % K)
		
		hash_buffer = b''
		hash_buffer += SSHBytes.to_bytes(client_id)
		print('client_id end : %s' % hex(len(hash_buffer)))
		hash_buffer += SSHBytes.to_bytes(server_id)
		print('server_id end : %s' % hex(len(hash_buffer)))
		hash_buffer += SSHBytes.to_bytes(client_kexinit_payload)
		print('client_kexinit_payload end : %s' % hex(len(hash_buffer)))
		hash_buffer += SSHBytes.to_bytes(server_kexinit_payload)
		print('server_kexinit_payload end : %s' % hex(len(hash_buffer)))
		hash_buffer += server_host_key.to_bytes()
		print('server_host_key end : %s' % hex(len(hash_buffer)))
		hash_buffer += SSHBytes.to_bytes(MPInt.int2bytes_padded(client_msg.e))
		print('client_msg.e end : %s' % hex(len(hash_buffer)))
		hash_buffer += SSHBytes.to_bytes(MPInt.int2bytes_padded(self.f))
		print('self.f end : %s' % hex(len(hash_buffer)))
		hash_buffer += SSHBytes.to_bytes(K)
		
		print(hexdump(hash_buffer))
		
		print('Hash buffer: %s' % hash_buffer.hex())
		
		H = self.kex_hash(hash_buffer).digest()#H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
		session_id =  H
		print('H: %s' % H.hex())
		
		K_enc = SSHBytes.to_bytes(K)
		self.c2s_init_IV = self.kex_hash(K_enc + H + b'A' + session_id).digest() # Initial IV client to server: HASH(K || H || "A" || session_id)
		self.s2c_init_IV = self.kex_hash(K_enc + H + b'B' + session_id).digest() # o   Initial IV server to client: HASH(K || H || "B" || session_id)
		self.c2s_cipher_key = self.kex_hash(K_enc + H + b'C' + session_id).digest() #o  Encryption key client to server: HASH(K || H || "C" || session_id)
		self.s2c_cipher_key = self.kex_hash(K_enc + H + b'D' + session_id).digest() #o  Encryption key server to client: HASH(K || H || "D" || session_id)
		self.c2s_integrity_key = self.kex_hash(K_enc + H + b'E' + session_id).digest() #o  Integrity key client to server: HASH(K || H || "E" || session_id)
		self.s2c_integrity_key = self.kex_hash(K_enc + H + b'F' + session_id).digest() #o  Integrity key server to client: HASH(K || H || "F" || session_id)
		
		print('A: %s' % self.c2s_init_IV.hex())
		print('B: %s' % self.s2c_init_IV.hex())
		print('C: %s' % self.c2s_cipher_key.hex())
		print('D: %s' % self.s2c_cipher_key.hex())
		print('E: %s' % self.c2s_integrity_key.hex())
		print('F: %s' % self.s2c_integrity_key.hex())

		self.server_cipher = AESModeOfOperationCTR(self.s2c_cipher_key[:16], Counter(int.from_bytes(self.s2c_init_IV[:16], byteorder = 'big', signed = False) ))
		self.client_cipher = AESModeOfOperationCTR(self.c2s_cipher_key[:16], Counter(int.from_bytes(self.c2s_init_IV[:16], byteorder = 'big', signed = False) ))
		self.server_hmac = hmac.new(self.s2c_integrity_key, digestmod=hashlib.sha1)
		self.client_hmac = hmac.new(self.c2s_integrity_key, digestmod=hashlib.sha1)
		
		h_sig = SSHRSASignatureData()
		h_sig.rsa_signature_blob = pkey.sign(H)
		
		payload = SSH2_MSG_KEXDH_REPLY()
		payload.pubkey_string = server_host_key
		payload.f = self.f
		payload.h_sig = h_sig
		
		return payload
		
		
		
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
				#print(message_type)
				packet.payload = type2msg[message_type].from_bytes(data[1:(packet.packet_length - packet.padding_length)])
				packet.random_padding = data[-packet.padding_length:]
				packet.mac = None
				return packet
			else:
				blocksize = 16
				packet_length_enc = await readexactly_or_exc(reader, blocksize)
				print(packet_length_enc)
				packet_length_dec = cipher.client_cipher.decrypt(packet_length_enc)
				print(packet_length_dec)
				packet.packet_length = int.from_bytes(packet_length_dec[:4], byteorder = 'big', signed = False)
				print(packet.packet_length)
				if packet.packet_length > MAX_PACKET_LENGTH:
					raise Exception('SSH packet too large!')
				data_enc = await readexactly_or_exc(reader, packet.packet_length)
				data = packet_length_dec[4:] + cipher.client_cipher.decrypt(data_enc)
				packet.padding_length = data[0]
				print(data)
				message_type = SSHMessageNumber(data[1])
				#print(message_type)
				packet.payload = type2msg[message_type].from_bytes(data[1:(packet.packet_length - packet.padding_length)])
				packet.random_padding = data[-packet.padding_length:]
				packet.mac = await readexactly_or_exc(reader, self.client_hmac.digest_size) 
				return packet

		except Exception as e:
			print(e)
			
	@staticmethod
	def from_bytes(data):
		return SSHParser.from_buffer(io.BytesIO(data))	
	
	@staticmethod
	def from_buffer(buff):
		packet = SSHPacket()
		packet.packet_length = int.from_bytes(buff.read(4), byteorder = 'big', signed = False)
		data = buff.read(packet.packet_length)
		packet.padding_length = data[0]
		message_type = SSHMessageNumber(data[1])
		packet.payload = type2msg[message_type].from_bytes(data[1:(packet.packet_length - packet.padding_length)])
		packet.random_padding = data[-packet.padding_length:]
		packet.mac = None
		return packet
		