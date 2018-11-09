startup = {
	'mode'    : 'DEV',  # STANDARD or DEV or SERVICE
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
				'level': 'INFO',
			}
		},
		'root'      : {
			'level'   : 'INFO',
			'handlers': ['console']
		}
	}
}

servers = []

remote_manager = {
	'mode' : 'SERVER',
	'config' : {},
	'listen_ip' : '127.0.0.1',
	'listen_port' : '9191',
}
