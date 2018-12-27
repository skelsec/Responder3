import enum
import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.TNS import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

class TNSSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.parser = TNSPacket
		self.firstpacket = True

	def __repr__(self):
		t = '== TNS Session ==\r\n'
		return t


class TNS(ResponderServer):
	def init(self):
		pass

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	@r3trafficlogexception
	async def run(self):

		# main loop
		while not self.shutdown_evt.is_set():
			try:
				result = await asyncio.gather(*[asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout=None)], return_exceptions=True)
			except asyncio.CancelledError as e:
				raise e
			if isinstance(result[0], R3ConnectionClosed):
				return
			elif isinstance(result[0], Exception):
				raise result[0]
			else:
				msg = result[0]

			print(msg)
			if self.session.firstpacket == True:
				ta = TNSResend()
				packet = TNSPacket()
				packet.payload = ta

				await self.send_data(packet.to_bytes())
				self.session.firstpacket = False
				continue

			if msg.header.packet_type == TNSPacketType.CONNECT:
				ta = TNSAccept()
				ta.version = 0x0134
				ta.service_flags = 0x0000
				ta.sdu_size = 0x0800
				ta.maximum_tdu_size = 0x7fff
				ta.byte_order = 256
				ta.data_length = None
				ta.data_offset = 24
				ta.flags1 = 65
				ta.flags2 = 1
				ta.padding = None
				ta.data = None
				packet = TNSPacket()
				packet.payload = ta

				await self.send_data(packet.to_bytes())

			elif msg.header.packet_type == TNSPacketType.DATA:
				t = "deadbeef00920a2001000004000004000300000000000400050a200100000800" +\
					"0100000b58884d7db000120001deadbeef000300000004000400010001000200" +\
					"01000300000000000400050a20010000020003e0e100020006fcff0002000200" +\
					"000000000400050a200100000c0001001106100c0f0a0b080201030003000200" +\
					"000000000400050a20010000030001000301"

				ta = TNSData()
				ta.flags = 0
				ta.data = bytes.fromhex(t)
				packet = TNSPacket()
				packet.payload = ta

				await self.send_data(packet.to_bytes())