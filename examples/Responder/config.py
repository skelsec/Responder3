startup = {
	'mode' : 'STANDARD', #STANDARD or DEV or SERVICE
	'settings' : {
		'pidfile' : "/var/run/responder.pid", #must be defined if mode==SERVICE, other modes ignore this
	},
}

##### GLOBAL SETTINGS
sslsettings = {
	'ciphers'  : 'ALL',
	'certfile' : '',#full file path please
	'keyfile'  : '' #full file path please
}

##### SERVERS
servers = [
	{
		'handler' : 'SMTP',
	},
	{
		'handler' : 'POP3',
	},
	{
		'handler' : 'IMAP',
	},
	{
		'handler' : 'FTP',
	},
	{
		'handler' : 'HTTP',
	},
	{
		'handler' : 'SMB',
	},
	{
		'handler' : 'NBTNS',
		'proto'   : 'UDP',  #protocol needs to be set because TCP is explicitly set
		'settings': {
						'mode': 'spoof', #mode can be either analyse or spoof
						'spoofTable': {
							'ALL' : '127.0.0.1', #ALL, or any valied regexp
						},

					}, 
	},
	{
		'handler' : 'LLMNR',
		'ip'      : '224.0.0.252',
		'port'    : 5355,
		'proto'   : 'UDP',
		'settings': {
						'mode': 'spoof', #mode can be either analyse or spoof
						'spoofTable': {
							'ALL' : '2001:0db8:85a3:0000:0000:8a2e:0370:7334', #ALL, or any valied regexp
						},
		
					}, 
	},
	
	{
		'handler' : 'DNS',
		'ip'      : '',
		'port'    : 53,
		'proto'   : 'TCP',
		'settings': {
						'mode': 'spoof', #mode can be either analyse or spoof
						'spoofTable': {
							'korte.com' : '::1', #ALL, or any valied regexp
							#'ALL' : '192.168.44.23', #ALL, or any valied regexp
						},
						'passthru' : {
							'dnsserver': '8.8.8.8:53',
							'bindIP' : ''
						},
		
					}, 
	},
	{
		'handler' : 'DNS',
		'ip'      : '',
		'port'    : 53,
		'proto'   : 'UDP',
		'settings': {
						'mode': 'spoof', #mode can be either analyse or spoof
						'spoofTable': {
							'korte.com' : '::1', #ALL, or any valied regexp
							#'ALL' : '192.168.44.23', #ALL, or any valied regexp
						},
						'passthru' : {
							'dnsserver': '8.8.8.8:53',
							'bindIP' : ''
						},
		
					}, 
	},
]

##### LOG SETTINGS
logsettings = {

	#### log extensions, only enable if the proper extension is installed!!!!!!
	'handlers':{
		#"twitter":"twitter",
		#"webview":"webview",
		#"webviewws":"webviewws"
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
		'SSLServerCert' : '',
		'SSLClientCert' : '',
		'SSLClientKey'  : '',
		'sendInterval'  : 10,
		'connectionEndpoint':'/connection/',
		'resultsEndpoint':'/result/'
	},
	'webviewws' : {
		'URL':'http://localhost:8081',
		'AgentId' : 'localagent',
		'SSLServerCert' : '',
		'SSLClientCert' : '',
		'SSLClientKey'  : ''

	},
	'email':
	{
		'writePath': '', #full file path please
	},

	##### PYTHON LOGGER SETTINGS
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
"""
	{
		'handler' : 'DNS',
		'ip'      : '',
		'port'    : 53,
		'proto'   : 'UDP',
		'settings': {
						'mode': 'spoof', #mode can be either analyse or spoof
						'spoofTable': {
							'ALL' : '::1', #ALL, or any valied regexp
							#'ALL' : '192.168.44.23', #ALL, or any valied regexp
						},
		
					}, 
	},

	{
		'handler' : 'MDNS',
		'ip'      : '224.0.0.251',
		'port'    : 5353,
		'proto'   : 'UDP',
		'settings': {
						'mode': 'spoof', #mode can be either analyse or spoof
						'spoofTable': {
							'ALL' : '127.0.0.1', #ALL, or any valied regexp
						},

					}, 
	},
	
"""
