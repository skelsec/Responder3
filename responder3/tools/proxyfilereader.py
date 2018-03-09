from responder3.core.commons import *

def print_packets(filename):
	with open(filename, 'r') as f:
		for line in f:
			line = line.strip()
			pd = ProxyData.fromJSON(line)
			print(str(pd))

if __name__ == '__main__':
	import argparse
	parser = argparse.ArgumentParser(description='Parse the prox log file and print each packet to stdout')
	parser.add_argument('filename', help='full path to the proxy log file')
	args =  parser.parse_args()
	print_packets(args.filename)
