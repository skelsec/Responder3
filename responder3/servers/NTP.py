import logging
import asyncio
import traceback
import ipaddress
import datetime

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.NTP import * 
from responder3.core.servertemplate import ResponderServer, ResponderServerSession, ResponderServerGlobalSession


class NTPGlobalSession(ResponderServerGlobalSession):
	def __init__(self, listener_socket_config, settings, log_queue):
		ResponderServerGlobalSession.__init__(self, log_queue, self.__class__.__name__)
		self.listener_socket_config = listener_socket_config
		self.settings = settings

		self.refid = ipaddress.IPv4Address('127.0.0.1')
		self.faketime = datetime.datetime.now()

		if self.settings:
			self.parse_settings()
			return
		self.set_default_settings()

	def set_default_settings(self):
		self.refid = ipaddress.IPv4Address('127.0.0.1')
		self.faketime = datetime.datetime.now()

	def parse_settings(self):
		fmt = '%b %d %Y %H:%M'
		if 'refid' in self.settings:
			self.refid = ipaddress.ip_address(self.settings['refid'])

		if 'faketime' in self.settings:			
			if 'timefmt' in self.settings:
				fmt = self.settings['timefmt']
			
			self.faketime = datetime.datetime.strptime(self.settings['faketime'], fmt)


class NTPSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.parser = NTPPacket


class NTP(ResponderServer):
	def init(self):
		pass
		
	async def send_data(self, data):
		self.cwriter.write(data)
		#await asyncio.wait_for(, timeout=1)
		return

	@r3trafficlogexception
	async def run(self):
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

		await self.logger.info('Time request in! Spoofing time to %s' % (self.globalsession.faketime.isoformat()))
		response = NTPPacket.construct_fake_reply(msg.TransmitTimestamp, self.globalsession.faketime, self.globalsession.refid)
			
		await asyncio.wait_for(self.send_data(response.to_bytes()), timeout=1)