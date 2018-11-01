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

from responder3.core import *
from responder3.servers import *
from responder3.poisoners import *

import config

def start_responder(bind_ifaces = None):
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

		#starting commin manager
		#commons.start_commons()

		man = multiprocessing.Manager()
		rdns = man.dict()
		logQ = multiprocessing.Queue()


		#Setting up logging
		lp = logprocess.LogProcessor(config.logsettings, logQ)
		lp.daemon = True
		lp.start()

		#Setting up and starting servers
		servers    = []
		serverProcesses = []
		
		for serverentry in config.servers:
			#handler = serverentry['handler']

			handler_module = getattr(sys.modules[__name__], serverentry['handler'])
			serverhandler  = getattr(handler_module, serverentry['handler'])
			sessionhandler = getattr(handler_module, '%s%s' % (serverentry['handler'], 'Session'))
			globalsessionhandler = getattr(handler_module, '%s%s' % (serverentry['handler'], 'GlobalSession'), None)

			serverentry['serverhandler'] = serverhandler
			serverentry['serversession'] = sessionhandler
			serverentry['globalsession'] = globalsessionhandler
			serverentry['shared_rdns'] = rdns
			serverentry['shared_logQ'] = logQ
			serverentry['interfaced'] = interfaceutil.interfaced

			if bind_ifaces is None:
				ifaces = serverentry.get('bind_iface', None)
				if ifaces is None:
					raise Exception('Interface name MUST be provided!')
				if not isinstance(ifaces, list):
					ifaces = [ifaces]

			else:
				ifaces = bind_ifaces

			bind_family = serverentry.get('bind_family', None)
			if bind_family is not None:
				bind_family = int(bind_family)
			ips = []
			for iface in ifaces:
				if bind_family is None:
					for ip in interfaceutil.interfaced[iface].IPv4:
						ips.append( (ip,iface, interfaceutil.interfaced[iface].ifindex))
					for ip in interfaceutil.interfaced[iface].IPv6:
						ips.append( (ip,iface, interfaceutil.interfaced[iface].ifindex))
				else:
					if bind_family == 4:
						for ip in interfaceutil.interfaced[iface].IPv4:
							ips.append( (ip,iface, interfaceutil.interfaced[iface].ifindex))
					else:
						for ip in interfaceutil.interfaced[iface].IPv6:
							ips.append( (ip,iface, interfaceutil.interfaced[iface].ifindex))

			portspecs = serverentry.get('bind_port', commons.defaultports[serverentry['handler']] if serverentry['handler'] in commons.defaultports else None)
			if portspecs is None:
				raise Exception('For protocol %s the port must be supplied!' % (serverentry['handler'], ))
			if not isinstance(portspecs, list):
				portspecs = [portspecs]
			
			for element in itertools.product(ips, portspecs):
				serverentry['bind_addr'] = element[0][0]
				serverentry['bind_iface'] = element[0][1]
				serverentry['bind_iface_idx'] = element[0][2]
				serverentry['bind_port'] = element[1][0]
				serverentry['bind_protocol'] = element[1][1]

				servers.append(serverprocess.ServerProperties.from_dict(serverentry))

		if len(servers) == 0:
			raise Exception('Did not start any servers! Possible reasons: 1. config file is wrong 2. the interface you specified is not up/doesnt have any IP configured')

		for server in servers:
			ss = serverprocess.ResponderServerProcess(server)
			ss.daemon = True
			serverProcesses.append(ss)
			ss.start()
	
		print('Started everything!')
		for server in serverProcesses:
			server.join()
		

	except KeyboardInterrupt:
		print('CTRL+C pressed, exiting!')
		sys.exit(0)

def main(argv):
	import argparse
	parser = argparse.ArgumentParser(description = 'Responder3')
	parser.add_argument("-I", action='append', help="Interface to bind to, can be multiple by providing sequential -I. Overrides bind_iface parameter in configs.")
	args = parser.parse_args()

	start_responder(args.I)


if __name__ == '__main__':
	main(sys.argv)
