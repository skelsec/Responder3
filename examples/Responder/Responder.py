#!/usr/bin/python3
import sys
import atexit
import copy
import os
import time
from multiprocessing import Manager
from pathlib import Path
from responder3.core import *
from responder3.servers.FTP import FTP
from responder3.servers.HTTP import HTTP, HTTPS
from responder3.servers.SMTP import SMTP
from responder3.servers.POP3 import POP3, POP3S
from responder3.servers.IMAP import IMAP, IMAPS
import config

def byealex(name_of_pid):
	pidfile = str(name_of_pid)
	os.remove(pidfile)

def handle_systemd():
	if os.path.isfile(config.pidfile):
		print ("%s already exists, exiting" % config.pidfile)
		sys.exit()

	pid = str(os.getpid())
	with open(config.pidfile, 'w') as f:
		f.write(pid)
	
	atexit.register(byealex,config.pidfile)
	

def main(argv):
	handle_systemd()
	try:
		manager = Manager() 
		rdnsd   = manager.dict() #shared dictionary across all processes to speed up rdns resolution
		current_path = Path(__file__)
		basedir = Path(str(current_path.parents[0]))

		bind_ip = ''

		httpsettings2 = copy.deepcopy(config.httpsettings)
		httpsettings2['Basic'] = True

		httpssettings = config.httpsettings
		httpssettings['SSL'] = config.sslsettings

		impassettings = {}
		impassettings['SSL'] = config.sslsettings

		pop3ssettings = {}
		pop3ssettings['SSL'] = config.sslsettings


		servers    = []
		resultQ   = multiprocessing.Queue()
		stopEvent = multiprocessing.Event()

		lp = LogProcessor(config.logsettings, resultQ, stopEvent)
		lp.daemon = True
		lp.start()
		
		ftpserver = Server('', 21, FTP, rdnsd)
		servers.append(ftpserver)
		httpserver = Server('', 80, HTTP, rdnsd, settings = config.httpsettings)
		servers.append(httpserver)
		httpserver2 = Server('', 81, HTTP, rdnsd, settings = httpsettings2)
		servers.append(httpserver2)
		httpsserver = Server('', 443, HTTPS, rdnsd, proto = ServerProtocol.SSL, settings = httpssettings)
		servers.append(httpsserver)
		smtpserver = Server('', 25, SMTP, rdnsd)
		servers.append(smtpserver)
		pop3server = Server('', 110, POP3, rdnsd)
		servers.append(pop3server)
		pop3sserver = Server('', 995, POP3S, rdnsd, proto = ServerProtocol.SSL, settings = pop3ssettings)
		servers.append(pop3sserver)
		imapserver = Server('', 143, IMAP, rdnsd)
		servers.append(imapserver)
		imapsserver = Server('', 993, IMAPS, rdnsd, proto = ServerProtocol.SSL, settings = impassettings)
		servers.append(imapsserver)

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