#!/usr/bin/env python3.6
import asyncio
from responder3.core.commons import *
from responder3.protocols.R3M import *


class R3ManagerClient:
	def __init__(self, loop):
		self.loop = loop
		self.host = '127.0.0.1'
		self.port = 55551
		self.ssl_ctx = None

	async def connect_responder(self):
		self.reader, self.writer = await asyncio.open_connection(self.host, self.port, loop=self.loop)

	async def send_command(self, cmd):
		self.writer.write(cmd.to_bytes())
		await self.writer.drain()
		return await Responder3Command.from_streamreader(self.reader)

	async def main(self):
		cmd = R3ServerListCommand()
		await self.connect_responder()
		await self.send_command(cmd)

def main():
	loop = asyncio.get_event_loop()
	client = R3ManagerClient(loop)
	loop.create_task(client.main())
	#loop.run_until_complete()
	loop.run_forever()

if __name__ == '__main__':
	main()
