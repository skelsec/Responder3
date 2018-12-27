import enum

class AUTHModuleMode(enum.Enum):
	CLIENT = 'CLIENT'
	SERVER = 'SERVER'

class AuthResult(enum.Enum):
	OK = enum.auto() #auth succsess, user is authorized
	FAIL = enum.auto() #auth failed, user creds not okay
	CONTINUE = enum.auto() #auth has multiple septs, more data needed

class AuthMecha(enum.Enum):
	BASIC  = 'BASIC'
	CRAM   = 'CRAM'
	DIGEST = 'DIGEST'
	SASL   = 'SASL'
	NTLM   = 'NTLM'

