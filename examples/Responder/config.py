pidfile = "/var/run/responder.pid"

logsettings = {
	'handlers':{
		"twitter":"twitter",
		"webview":"webview",
		"webviewwebsockets":"webviewwebsockets"
	},
	'twitter' : {
		"secrets" : {
			"consumer_key" : "",
			"consumer_secret" : "",
			"access_token_key" : "",
			"access_token_secret" : ""
		},
		"message_format" : "Here comes the next contestant!\r\nMODULE: {module}\r\nTYPE: {type}\r\nIP: {client}\r\nCreds: {fullhash}"
	},
	'webview' : {
		'URL':'http://localhost:8081',
		'AgentId' : 'localagent',
		'SSLAuth' : False,
		'SSLServerCert' : '',
		'SSLClientCert' : '',
		'SSLClientKey'  : '',
		'sendInterval'  : 10,
		'connectionEndpoint':'/connection/',
		'resultsEndpoint':'/result/'

	},
	'webviewwebsockets' : {
		'URL':'http://localhost:8081',
		'AgentId' : 'localagent',
		'SSLAuth' : False,
		'SSLServerCert' : '',
		'SSLClientCert' : '',
		'SSLClientKey'  : ''

	},


	'log' : {
		'version': 1,
		'formatters': {
			'detailed': {
				'class': 'logging.Formatter',
					'format': '%(asctime)s %(name)-15s %(levelname)-8s %(processName)-10s %(message)s'
			}
		},
		'handlers': {
			'console': {
				'class': 'logging.StreamHandler',
				'level': 'DEBUG',
			}
		},
		'root': {
			'level': 'DEBUG',
			'handlers': ['console']
		}
	}
}

httpsettings = {
	'Force_WPAD_Auth': False,
	'WPAD_Script': '',
	'NumChal' : "random",
	'Challenge' : '',
	'Serve_Always': False,
	'Serve_Exe': False,
	'Serve_Html': False,
	'Html_Filename': '',
	'Exe_Filename': '',
	'Exe_DlName': '',
	'Force_WPAD_Auth': False,
	'HtmlToInject': 'aaaa',
	'Basic' : False
	}

sslsettings = {
	'ciphers'  : 'ALL',
	'certfile' : './certs/responder.crt',
	'keyfile'  : './certs/responder.key'
}
