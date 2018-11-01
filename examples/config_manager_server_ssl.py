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
				'level': 'INFO',
			}
		},
		'root'      : {
			'level'   : 'INFO',
			'handlers': ['console']
		}
	}
}

#no servers in this example, we only focus on the results coming in from the client
servers = []

remote_manager = {
	'mode' : 'SERVER',
	'config' : {},
	'listen_ip' : '127.0.0.1',
	'listen_port' : '9191',
	'ssl_ctx' : {
		'protocols'  : 'PROTOCOL_SSLv23',
		'options'    : 'OP_CIPHER_SERVER_PREFERENCE',
		'verify_mode': 'CERT_REQUIRED',
		'server_side': True,
		'ciphers'    : 'ALL',
		'certfile'   : 'C:\\Users\\windev\\Desktop\\Responder3\\responder3\\tests\\testca\\test_server.crt',
		'keyfile'    : 'C:\\Users\\windev\\Desktop\\Responder3\\responder3\\tests\\testca\\test_server.pem',
		'cafile'     : 'C:\\Users\\windev\\Desktop\\Responder3\\responder3\\tests\\testca\\r3testCA.crt',
	},
	
}
