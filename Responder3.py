#!/usr/bin/python3.6
from responder3.core.responder3 import Responder3


def main():
	parser = Responder3.get_argparser()
	responder3 = Responder3.from_args(parser.parse_args())
	responder3.start()

if __name__ == '__main__':
	main()
