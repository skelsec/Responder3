#!/usr/bin/python3.6
import asyncio
from responder3.core.responder3 import Responder3


def main():
	loop = asyncio.get_event_loop()	
	
	parser = Responder3.get_argparser()
	responder3 = Responder3.from_args(parser.parse_args())
	loop.run_until_complete(responder3.run())
	#responder3.join()
	print('Responder finished!')

if __name__ == '__main__':
	main()
