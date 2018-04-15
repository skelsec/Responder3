import os
import sys
import copy
import json
import logging
import argparse
import itertools
import multiprocessing
import importlib.machinery
import importlib.util

from responder3.core.commons import handle_systemd, defaultports
from responder3.core.interfaceutil import interfaces
from responder3.core.logprocess import LogProcessor, LogEntry
from responder3.core.serverprocess import ResponderServerProcess


class Responder3:
	def __init__(self):
		self.config = None

		self.override_interfaces = None
		self.override_ipv4 = None
		self.override_ipv6 = None
		self.override_verb = None

		self.servers = []
		self.server_processes = []
		self.rdns = None
		self.logQ = None
		self.started = multiprocessing.Event()
		self.stop_event = multiprocessing.Event()

	@staticmethod
	def get_argparser():
		parser = argparse.ArgumentParser(
			description='Responder3',
			epilog='List of available interfaces:\r\n' + str(interfaces),
			formatter_class=argparse.RawTextHelpFormatter
		)
		parser.add_argument(
			"-c",
			"--config",
			help="Configuration file (JSON). Full path please"
		)
		parser.add_argument(
			"-p",
			"--python-config",
			help="Configuration file (Python). Full path please"
		)
		parser.add_argument(
			"-e",
			"--environ-config",
			action='store_true',
			help="Configuration file is set via OS environment variable (Python script)"
		)
		parser.add_argument(
			"-I",
			action='append',
			help="Interface to bind to, can be multiple by providing sequential -I. Overrides bind_iface parameter in configs."
		)
		parser.add_argument(
			"-4",
			action='store_true',
			dest='ip4',
			help="IP version 4 to be used. Overrides bind_family in config settings."
		)
		parser.add_argument(
			"-6",
			action='store_true',
			dest='ip6',
			help="IP version 6 to be used. Overrides bind_family in config settings."
		)
		parser.add_argument(
			"-L",
			action='store_true',
			dest='list_interfaces',
			help="List all interfaces with assigned IPv4 and IPv6 addresses then exit."
		)
		parser.add_argument(
			'-v',
			'--verbose',
			action='count',
			default=0
		)
		return parser

	@staticmethod
	def from_args(args):
		responder = Responder3()
		responder.override_interfaces = args.I
		responder.override_ipv4 = args.ip4
		responder.override_ipv6 = args.ip6
		responder.override_verb = args.verbose
		if args.config is not None:
			print(args.config)
			responder.config = Responder3Config.from_file(args.config)
		elif args.python_config is not None:
			responder.config = Responder3Config.from_python_script(args.config)
		elif args.environ_config is not None:
			responder.config = Responder3Config.from_os_env()
		else:
			raise Exception(
				'No suitable configuration method was supplied!'
				'Use either -e or -c or -p'
			)
		return responder

	@staticmethod
	def from_config(config, override_interfaces = None, override_ipv4 = None, override_ipv6=None, override_verb=None):
		responder = Responder3()
		responder.override_interfaces = override_interfaces
		responder.override_ipv4 = override_ipv4
		responder.override_ipv6 = override_ipv6
		responder.override_verb = override_verb
		responder.config = config
		return responder

	def start_process(self):
		p = multiprocessing.Process(target=self.start, args=())
		p.start()
		return p

	def log(self, message, level=logging.INFO):
		log = LogEntry(level, 'Responder3 MAIN', message)
		self.logQ.put(log)

	def start(self):
		try:
			if self.config.startup is not None:
				if 'mode' in self.config.startup:
					if self.config.startup['mode'] == 'STANDARD':
						# starting in standalone mode...
						pass
					elif self.config.startup['mode'] == 'DEV':
						os.environ['PYTHONASYNCIODEBUG'] = '1'
						os.environ['R3DEEPDEBUG'] = '1'

					elif self.config.startup['mode'] == 'SERVICE':
						if 'pidfile' not in self.config.startup['mode']:
							raise Exception('pidfile MUST be set when running in service mode')
						handle_systemd(self.config.startup['mode']['pidfile'])

				else:
					# starting in standalone mode...
					pass
			else:
				# starting in standalone mode...
				pass

			man = multiprocessing.Manager()
			self.rdns = man.dict()
			self.logQ = multiprocessing.Queue()

			# Setting up logging
			lp = LogProcessor(self.config.log_settings, self.logQ)
			lp.daemon = True
			lp.start()

			# Setting up and starting servers
			for serverentry in self.config.server_settings:
				if self.override_interfaces is None:
					ifaces = serverentry.get('bind_iface', None)
					if ifaces is None:
						raise Exception('Interface name MUST be provided!')
					if not isinstance(ifaces, list):
						ifaces = [ifaces]

				else:
					ifaces = self.override_interfaces

				bind_family = []
				if self.override_ipv4:
					bind_family.append(4)
				if self.override_ipv6:
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

				portspecs = serverentry.get(
					'bind_port',
					defaultports[serverentry['handler']] if serverentry['handler'] in defaultports else None
				)

				if portspecs is None:
					raise Exception('For protocol %s the port must be supplied!' % (serverentry['handler'],))

				if not isinstance(portspecs, list):
					portspecs = [portspecs]

				for element in itertools.product(ifaces, portspecs):
					socket_configs = interfaces.get_socketconfig(
						element[0], element[1][0], element[1][1],
						ipversion=bind_family
					)
					for socket_config in socket_configs:
						serverentry['listener_socket_config'] = socket_config

						temp = copy.deepcopy(serverentry)
						temp['shared_rdns'] = self.rdns
						temp['shared_logQ'] = self.logQ

						self.servers.append(temp)

			if len(self.servers) == 0:
				raise Exception(
					'Did not start any servers! '
					'Possible reasons:'
					'1. config file is wrong'
					'2. the interface you specified is not up/doesnt have any IP configured'
				)

			for server in self.servers:
				ss = ResponderServerProcess.from_dict(server)
				ss.daemon = True
				self.server_processes.append(ss)
				ss.start()

			self.log('Started all servers')
			self.started.set()
			for server in self.server_processes:
				server.join()

		except KeyboardInterrupt:
			self.log('CTRL+C pressed, exiting!')
			sys.exit(0)


class Responder3Config:
	CONFIG_OS_KEY = 'R3CONFIG'

	def __init__(self):
		self.startup = None
		self.log_settings = None
		self.server_settings = None

	@staticmethod
	def from_dict(config):
		conf = Responder3Config()
		conf.startup = config['startup']
		conf.log_settings = config['logsettings']
		conf.server_settings = config['servers']
		return conf

	@staticmethod
	def from_json(config_data):
		return Responder3Config.from_dict(json.loads(config_data))

	@staticmethod
	def from_file(file_path):
		with open(file_path, 'r') as f:
			config = json.load(f)
		return Responder3Config.from_dict(config)

	@staticmethod
	def from_python_script(file_path):
		loader = importlib.machinery.SourceFileLoader('responderconfig', file_path)
		spec = importlib.util.spec_from_loader(loader.name, loader)
		responderconfig = importlib.util.module_from_spec(spec)
		loader.exec_module(responderconfig)
		conf = Responder3Config()
		conf.startup = responderconfig.startup
		conf.log_settings = responderconfig.logsettings
		conf.server_settings = responderconfig.servers

		return conf

	@staticmethod
	def from_os_env():
		config_file = os.environ.get(Responder3Config.CONFIG_OS_KEY)
		if config_file is None:
			raise Exception(
				'Could not find configuration file path in os environment variables!'
				'Name to be set: %s' % Responder3Config.CONFIG_OS_KEY
			)
		return Responder3Config.from_python_script(config_file)
