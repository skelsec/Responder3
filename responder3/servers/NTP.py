import logging
import asyncio
import traceback
import ipaddress
import datetime

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

		self.parse_settings()

	def parse_settings(self):
		fmt = '%b %d %Y %H:%M'
		###### PARSING SETTINGS IF ANY
		if self.settings is None:
			return

		if 'refID' in self.settings:
			self.refid = ipaddress.ip_address(self.settings['refid'])

		if 'faketime' in self.settings:			
			if 'fakeTimeFmt' in self.settings:
				fmt = self.settings['fakeTimeFmt']
			
			self.faketime = datetime.datetime.strptime(self.settings['faketime'], fmt)


class NTPSession(ResponderServerSession):
	pass


class NTP(ResponderServer):
	def init(self):
		self.parser = NTPmsg

	async def parse_message(self):
		return self.parser.from_buffer(self.creader.buff)

	async def send_data(self, data):
		await asyncio.wait_for(self.cwriter.write(data), timeout=1)
		return

	async def run(self):
		try:
			msg = await asyncio.wait_for(self.parse_message(), timeout=1)
			await self.log('Time request in! Spoofing time to %s' % (self.globalsession.faketime.isoformat()))
			response = NTPmsg.construct_fake_reply(msg.TransmitTimestamp, self.globalsession.faketime, self.globalsession.refid)
			
			await asyncio.wait_for(self.send_data(response.toBytes()), timeout=1)

		except Exception as e:
			traceback.print_exc()
			await self.log('Exception! %s' % (str(e),))
			pass