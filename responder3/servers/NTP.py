import logging
import asyncio
import traceback
import ipaddress
import datetime

from responder3.core.commons import *
from responder3.protocols.NTP import * 
from responder3.core.udpwrapper import UDPClient
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class NTPGlobalSession():
	def __init__(self, server_properties):
		self.server_properties = server_properties
		self.settings = server_properties.settings

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
		self.parser = NTPPacket

	@asyncio.coroutine
	def parse_message(self):
		return self.parser.from_buffer(self.creader.buff)

	@asyncio.coroutine
	def send_data(self, data):
		yield from asyncio.wait_for(self.cwriter.write(data), timeout=1)
		return

	@asyncio.coroutine
	def run(self):
		try:
			msg = yield from asyncio.wait_for(self.parse_message(), timeout=1)
			self.log('Time request in! Spoofing time to %s' % (self.globalsession.faketime.isoformat()))
			response = NTPPacket.construct_fake_reply(msg.TransmitTimestamp, self.globalsession.faketime, self.globalsession.refid)
			
			yield from asyncio.wait_for(self.send_data(response.toBytes()), timeout=1)

		except Exception as e:
			traceback.print_exc()
			self.log('Exception! %s' % (str(e),))
			pass