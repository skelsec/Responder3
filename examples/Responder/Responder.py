#!/usr/bin/python3.6
import sys
import atexit
import copy
import os
import time
import logging
import itertools
import importlib
from multiprocessing import Manager
from pathlib import Path
from responder3.core import *
from responder3 import utils
from responder3.servers.FTP import FTP
from responder3.servers.HTTP import HTTP, HTTPS
from responder3.servers.SMTP import SMTP
from responder3.servers.POP3 import POP3, POP3S
from responder3.servers.IMAP import IMAP, IMAPS
from responder3.servers.SMB import SMB
from responder3.poisoners.NBTNS import NBTNS
from responder3.poisoners.LLMNR import LLMNR
from responder3.poisoners.DNS import DNS
from responder3.poisoners.MDNS import MDNS

import config

def byealex(name_of_pid):
	pidfile = str(name_of_pid)
	os.remove(pidfile)

def handle_systemd(pidfile):
	if os.path.isfile(pidfile):
		print ("%s already exists, exiting" % pidfile)
		sys.exit()

	pid = str(os.getpid())
	with open(pidfile, 'w') as f:
		f.write(pid)
	
	atexit.register(byealex,pidfile)

def main(argv):
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
					handle_systemd(config.startup['mode']['pidfile'])

			else:
				#starting in standalone mode...
				pass
		else:
			#starting in standalone mode...
			pass
		
		
		manager = Manager() 
		rdnsd   = manager.dict() #shared dictionary across all processes to speed up rdns resolution
		current_path = Path(__file__)
		basedir = Path(str(current_path.parents[0]))


		servers    = []
		resultQ   = multiprocessing.Queue()
		stopEvent = multiprocessing.Event()

		lp = LogProcessor(config.logsettings, resultQ, stopEvent)
		lp.daemon = True
		lp.start()

		for serverentry in config.servers:
			#handler = serverentry['handler']
			handler = getattr(sys.modules[__name__], serverentry['handler'])
			ports = serverentry.get('port', utils.defaultports[serverentry['handler']])
			if not isinstance(ports, list):
				ports = [ports]
			
			ips   = serverentry.get('ip')
			if not isinstance(ips, list):
				ips = [ips]

			for element in itertools.product(ips, ports):
				servers.append(Server(element[0], element[1], handler, rdnsd, 
										proto = serverentry.get('proto'),
										settings = serverentry.get('settings'),
										sslsettings = serverentry.get('sslsettings')))
		
		for server in servers:
			ss = AsyncSocketServer(server, resultQ)
			ss.daemon = True
			ss.start()
	
		print('Started everything!')
		ss.join()
		

	except KeyboardInterrupt:
		sys.exit(0)


if __name__ == '__main__':
	main(sys.argv)
