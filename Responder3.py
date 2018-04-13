#!/usr/bin/python3.6

import os
import sys
import copy
import atexit
import logging
import itertools
import importlib
import multiprocessing
from pathlib import Path

from responder3.core import commons
from responder3.core.interfaceutil import interfaces
from responder3.core import logprocess
from responder3.core import serverprocess

import config


def start_responder(bind_ifaces = None, bind_ipv4 = False, bind_ipv6 = False):
	try:
		if hasattr(config, 'startup'):
			if 'mode' in config.startup:
				if config.startup['mode'] == 'STANDARD':
					#starting in standalone mode...
					pass
				elif config.startup['mode'] == 'DEV':
					os.environ['PYTHONASYNCIODEBUG'] = '1'
					os.environ['R3DEEPDEBUG'] = '1'

				elif config.startup['mode'] == 'SERVICE':
					if 'pidfile' not in config.startup['mode']:
						raise Exception('pidfile MUST be set when running in service mode')
					commons.handle_systemd(config.startup['mode']['pidfile'])

			else:
				#starting in standalone mode...
				pass
		else:
			#starting in standalone mode...
			pass

		current_path = Path(__file__)
		basedir = Path(str(current_path.parents[0]))

		man = multiprocessing.Manager()
		rdns = man.dict()
		logQ = multiprocessing.Queue()

		# Setting up logging
		lp = logprocess.LogProcessor(config.logsettings, logQ)
		lp.daemon = True
		lp.start()

		# Setting up and starting servers
		servers = []
		serverProcesses = []
		
		for serverentry in config.servers:
			#handler = serverentry['handler']

			if bind_ifaces is None:
				ifaces = serverentry.get('bind_iface', None)
				if ifaces is None:
					raise Exception('Interface name MUST be provided!')
				if not isinstance(ifaces, list):
					ifaces = [ifaces]

			else:
				ifaces = bind_ifaces

			bind_family = []
			if bind_ipv4:
				bind_family.append(4)
			if bind_ipv6:
				bind_family.append(6)

			if bind_family == []:
				bind_family_conf = serverentry.get('bind_family', None)
				if bind_family_conf is not None:
					if not isinstance(bind_family_conf, list):
						bind_family.append(int(bind_family_conf))
					else:
						for ver in bind_family_conf:
							bind_family.append(int(ver))

			if bind_family == []:
				raise Exception('IP version (bind_family) MUST be set either in cofig file or in command line!')

			portspecs = serverentry.get('bind_port', commons.defaultports[serverentry['handler']] if serverentry['handler'] in commons.defaultports else None)
			if portspecs is None:
				raise Exception('For protocol %s the port must be supplied!' % (serverentry['handler'], ))
			if not isinstance(portspecs, list):
				portspecs = [portspecs]

			for element in itertools.product(ifaces, portspecs):
				socket_configs = interfaces.get_socketconfig(element[0], element[1][0], element[1][1], ipversion = bind_family)
				for socket_config in socket_configs:
					serverentry['listener_socket'] =  socket_config

					temp = copy.deepcopy(serverentry)
					temp['shared_rdns'] = rdns
					temp['shared_logQ'] = logQ

					# print(serverentry)
					servers.append(temp)

		if len(servers) == 0:
			raise Exception('Did not start any servers! Possible reasons: 1. config file is wrong 2. the interface you specified is not up/doesnt have any IP configured')

		for server in servers:
			ss = serverprocess.ResponderServerProcess.from_dict(server)
			ss.daemon = True
			serverProcesses.append(ss)
			ss.start()
		

		# print('Started everything!')
		for server in serverProcesses:
			server.join()
		

	except KeyboardInterrupt:
		print('CTRL+C pressed, exiting!')
		sys.exit(0)

def main(argv):
	import argparse
	import pprint
	parser = argparse.ArgumentParser(description = 'Responder3',
									 epilog      = 'list of available interfaces:\r\n' + str(interfaces),
									 formatter_class = argparse.RawTextHelpFormatter)
	parser.add_argument("-I", action='append', help="Interface to bind to, can be multiple by providing sequential -I. Overrides bind_iface parameter in configs.")
	parser.add_argument("-4", action='store_true', dest='ip4', help="IP version 4 to be used. Overrides config settings.")
	parser.add_argument("-6", action='store_true', dest='ip6', help="IP version 6 to be used. Overrides config settings.")
	parser.add_argument("-L", action='store_true', dest='list_interfaces', help="List all interfaces with assigned IPv4 and IPv6 addresses then exit.")
	
	args = parser.parse_args()

	if args.list_interfaces:
		str(interfaces)
		sys.exit()
	start_responder(args.I, args.ip4, args.ip6)


if __name__ == '__main__':
	main(sys.argv)
