startup = {
	'mode'    : 'STANDARD',  # STANDARD or DEV or SERVICE
	'settings': {
		'pidfile': "/var/run/responder.pid",  # must be defined if mode==SERVICE, other modes ignore this
	},
}

logsettings = {
	'log': {
		'version'   : 1,
		'formatters': {
			'detailed': {
				'class' : 'logging.Formatter',
				'format': '%(asctime)s %(name)-15s %(levelname)-8s %(processName)-10s %(message)s'
			}
		},
		'handlers'  : {
				'console': {
					'class': 'logging.StreamHandler',
					'level': 'DEBUG',
				},
				'file': {
					'class': 'logging.handlers.RotatingFileHandler',
					'level': 'DEBUG',
					'formatter': 'detailed',
					'filename': 'coffeelog.txt',
					'mode': 'a',
					'maxBytes': 0,
					'backupCount': 0,
				},
		},
		'root'      : {
			'level'   : 'DEBUG',
			'handlers': ['console', 'file']
		}
	}
}

servers = [
	{
		'handler' : 'MDNS',
		'settings': {
			'mode'      : 'analyse',
		},
	},
	{
		'handler'    : 'DNS',
		'bind_family': 4,
		'settings'   : {
			'mode'      : 'analyse',  # mode can be either analyse or spoof
		},
	},
	{
		'handler' : 'LLMNR',
		'settings': {
			'mode'      : 'analyse',
		},
	},
	{
		'handler'    : 'NBTNS',
		'bind_family': 4,  # no point in ipv6, it's not supported by design (but it works with it regardless :P)
		'settings'   :{
			'mode'      : 'analyse',  # mode can be either analyse or spoof
		},
	},
	{
		'bind_family': 4,
		'handler'    : 'DHCP',
		'settings'   : {
			'mode'       : 'analyse',  # mode can be either analyse or spoof
		},
	},
]
