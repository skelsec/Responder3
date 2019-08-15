#!/usr/bin/python3
import sys
import asyncio
from responder3.core.responder3 import Responder3


def main():
	loop = asyncio.get_event_loop()	
	
	parser = Responder3.get_argparser()
	if len(sys.argv) < 2:
		parser.print_usage()
		return

	responder3 = Responder3.from_args(parser.parse_args())
	#returns None if there is nothing to run (like listing interfaces)
	
	if responder3:
		loop.run_until_complete(responder3.run())
		print('Responder finished!')

if __name__ == '__main__':
	main()
