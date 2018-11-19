#https://tools.ietf.org/html/rfc1282
import io
import enum
import asyncio
import traceback

from responder3.core.logging.log_objects import Credential
from responder3.core.commons import read_element
from responder3.core.asyncio_helpers import *


class RloginSessionState:
	BEFORE_AUTH = enum.auto()
	AFTER_AUTH = enum.auto()

class AuthenticationMessage:
	def __init__(self):
		self.user_name = None
		self.server_name = None
		self.terminal_type = None
		self.terminal_speed = None

	async def from_streamreader(reader, timeout = 60):
		am = AuthenticationMessage()
		t = await readexactly_or_exc(reader, 1, timeout=timeout)
		if t != b'\x00':
			raise Exception('Wrong protocol!')

		user = await readuntil_or_exc(reader, b'\x00', timeout=timeout)
		am.user_name = user.decode()

		server = await readuntil_or_exc(reader, b'\x00', timeout=timeout)
		am.server_name = server.decode()

		terminal = await readuntil_or_exc(reader, b'\x00', timeout=timeout)
		am.terminal_type, am.terminal_speed = terminal.decode().split('/')

		return am

	def to_bytes(self):
		t = b'\x00'
		t += self.user_name.encode() + b'\x00'
		t += self.server_name.encode() + b'\x00'
		t += self.terminal_type.encode() + b'\x00'
		return t

	def to_credential(self):
		return Credential('PLAIN',
						  username=self.user_name,
						  fullhash='%s:%s' % (self.user_name, '')
						  )