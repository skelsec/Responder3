import enum
import logging
import asyncio

from responder3.core.logging.logger import *
from responder3.core.asyncio_helpers import R3ConnectionClosed
from responder3.core.commons import *
from responder3.protocols.MYSQL import *
from responder3.core.servertemplate import ResponderServer, ResponderServerSession

async def mysql_test(ip, loop):
	try:
		reader, writer = await asyncio.open_connection('127.0.0.1', 3306, loop=loop)
		t_length = await readexactly_or_exc(reader, 3)
		length = int.from_bytes(t_length,byteorder = 'little', signed = False)
		data = await readexactly_or_exc(reader, length)

		handshake = HandshakeV10.from_bytes(t_length + data)

		sequence_id = handshake.sequence_id + 1

		resp = HandshakeResponse41_test(sequence_id)
		writer.write(resp.to_bytes())

	except Exception as e:
		print('ERROR! %s' % e)




if __name__ == '__main__':
	ip = '127.0.0.1'

	loop = asyncio.get_event_loop()
	loop.run_until_complete(mysql_test(ip, loop))
	loop.close()