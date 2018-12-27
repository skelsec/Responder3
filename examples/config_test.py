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

servers = [
	{
		'handler'    : 'FTP',
	},
	{
		'handler'    : 'HTTP',
		'settings'   : {
			'authentication':{
				'auth_mecha' : 'BASIC',
			},
		}
	},
	{
		'handler'    : 'SMTP',
	},
	{
		'handler'    : 'POP3',
	},
	{
		'handler'    : 'IMAP',
	},
	{
		'handler'    : 'KERBEROS',
	},
	{
		'handler'    : 'LDAP',
	},
	{
		'handler'    : 'VNC',
	},
	{
		'handler'    : 'SOCKS5',
	},
	{
		'handler'    : 'TELNET',
	},
	{
		'handler'    : 'RLOGIN',
	},
	{
		'handler'    : 'MYSQL',
	},
	{
		'handler'    : 'TNS',
	},
	{
		'handler'    : 'MSSQL',
	},
	{
		'handler'    : 'SMB',
	},
	{
		'handler'    : 'SIP',
		'bind_port'  : [(5060, 'udp')],
	}
]

