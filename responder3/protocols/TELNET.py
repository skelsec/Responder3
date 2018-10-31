#https://tools.ietf.org/html/rfc854
#https://tools.ietf.org/html/rfc861
"""
Foreword: THIS IS NOT THE TELNET PROTOCOL!
Telnet clients nowadays just use a half-assed ASCII based tcp socket,
but telnet is much much more than that!!!!

That being sad, if someone want's to do actual telnet implementation 
I'm willing to buy him a beer or two, if it can do pretty terminals.

Now enjoy this half-assed protocol impelemtation from yours truly!
"""
import enum
import io

from responder3.core.commons import *
from responder3.core.asyncio_helpers import *

class TELNETMessageParser:
	def __init__(self, session):
		self.session = session
		
	async def from_streamreader(self, reader, timeout = 60):
		first = await read_or_exc(reader, 1, timeout = timeout)
		if first[0] == 255:
			#extended options list
			data = await read_or_exc(reader, 26, timeout = timeout)
			return first + data
		else:
			data = await readline_or_exc(reader, timeout = timeout)
			return (first + data[:-2]).decode()