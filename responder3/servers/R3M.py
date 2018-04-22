import logging
import asyncio

from responder3.core.commons import *
from responder3.protocols.R3M import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession


class R3MSession(ResponderServerSession):
	def __init__(self, connection, log_queue):
		ResponderServerSession.__init__(self, connection, log_queue, self.__class__.__name__)
		self.parser = Responder3Command
		self.r3 = None
		self.result_queue = None
		self.close_session = asyncio.Event()

	def __repr__(self):
		t = '== R3M Session ==\r\n'
		t += 'parser:      %s\r\n' % repr(self.parser)
		t += 'r3:      %s\r\n' % repr(self.r3)
		t += 'result_queue:      %s\r\n' % repr(self.result_queue)
		return t


class R3M(ResponderServer):
	def init(self):
		self.parse_settings()

	def parse_settings(self):
		self.session.r3 = self.settings['r3']
		self.session.result_queue = self.settings['result_queue']

	async def parse_message(self, timeout=None):
		try:
			req = await asyncio.wait_for(self.session.parser.from_streamreader(self.creader), timeout=timeout)
			return req
		except asyncio.TimeoutError:
			await self.log('Timeout!', logging.DEBUG)

	async def send_data(self, data):
		self.cwriter.write(data)
		await self.cwriter.drain()

	async def run(self):
		try:
			# main loop
			while True:
				cmd = await asyncio.wait_for(self.parse_message(), timeout=None)
				if cmd is None:
					# connection closed exception happened in the parsing
					self.session.close_session.set()
					continue
				print(cmd)
				if cmd.command == R3CommandType.GET_SERVER_LIST:
					r = R3ServerListReply.construct(self.session.r3.get_server_list())
					await self.send_data(r.to_bytes())
				else:
					self.log('Command not implemented!')


		except Exception as e:
			await self.log_exception()
			return
