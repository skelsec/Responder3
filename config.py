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
		'handler'    : 'GenericProxy',
		'bind_family': 4,
		'bind_port': [(443, 'tcp')],
		'bind_ip': '5.135.2.1',
		'bind_sslctx': {
			'protocols'  : 'PROTOCOL_SSLv23',
			'options'    : 'OP_CIPHER_SERVER_PREFERENCE',
			'verify_mode': 'CERT_REQUIRED',
			'server_side': True,
			'ciphers'    : 'ALL',
			'certfile'   : 'C:\\Users\\bisecur\\Desktop\\garagedoor_gh\\fake_cert.pem',
			'keyfile'    : 'C:\\Users\\bisecur\\Desktop\\garagedoor_gh\\fake_cert.key',
			'cafile'     : 'C:\\Users\\bisecur\\Desktop\\garagedoor_gh\\fake_ca.pem',
				
		},
		'settings'   : {
			'remote_host'      : '5.135.3.56',
			'remote_port'      : 443,
			'remote_sslctx'    : {
				'protocols'  : 'PROTOCOL_SSLv23',
				'options'    : 'OP_CIPHER_SERVER_PREFERENCE',
				'verify_mode': 'CERT_REQUIRED',
				'server_side': False,
				'ciphers'    : 'ALL',
				'certfile'   : 'C:\\Users\\bisecur\\Desktop\\garagedoor_gh\\pySecur\\pysecur3\\client.pem',
				'keyfile'    : 'C:\\Users\\bisecur\\Desktop\\garagedoor_gh\\pySecur\\pysecur3\\client.key',
			},
		},
	},
    {
		'handler'    : 'DNS',
		'bind_family': 4,
		'settings'   : {
			'mode'      : 'spoof',  # mode can be either analyse or spoof
			'spooftable' : [
				{
					'sslbiseclan.itbcloud.de' : '5.135.2.1',
				},
				{
					'pool.ntp.org' : '5.135.2.1',
				},
			],
		},
	},
	{
		'handler'    : 'NTP',
		'bind_family': 4,
		'settings': {
			'faketime' : 'Apr 27 2018 13:37'
		
		}
	},
    {
		'bind_family': 4,
		'handler'    : 'DHCP',
		'settings'   : {
			'mode'       : 'spoof',  # mode can be either analyse or spoof
            'subnetmask' : 'FF:FF:FF:00',
            'ip_pool'    : '5.135.2.100-200',
		},
	},
	{
		'handler'    : 'MDNS',
		'bind_family': 4,
	},
	{
		'handler'    : 'LLMNR',
		'bind_family': 4,
		'settings': {
			'mode'       : 'spoof',
			'spooftable' : {
						'alma' : '5.135.2.1',
			},
		},
	},

]

