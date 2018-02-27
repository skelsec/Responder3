
#https://tools.ietf.org/html/rfc1510
#https://github.com/wbond/asn1crypto/blob/master/docs/universal_types.md
#https://github.com/wbond/asn1crypto/blob/master/asn1crypto/core.py
#https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
#https://www.cloudshark.org/captures/fa35bc16bbb0?filter=frame%20and%20raw%20and%20ip%20and%20udp%20and%20kerberos
from asn1crypto.core import ObjectIdentifier,Choice, Any, SequenceOf, BitString, Sequence, GeneralString, OctetString, Enumerated, Integer, GeneralizedTime

class Realm(GeneralString):
        pass

"""
class Name(GeneralString):
        pass
"""

class KerberosTime(GeneralizedTime):
        pass

class APOptions(BitString):
        _map = {
                0: 'reserved',
                1: 'use-session-key',
                2: 'mutual-required',
        }

class TicketFlags(BitString):
        _map = {
                0: 'reserved',
                1: 'forwardable',
                2: 'forwarded',
                3: 'proxiable',
                4: 'proxy',
                5: 'may-postdate',
                6: 'postdated',
                7: 'invalid',
                8: 'renewable',
                9: 'initial',
                10: 'pre-authent',
                11: 'hw-authent',
        }

class KDCOptions(BitString):
        _map = {
                0: 'reserved',
                1: 'forwardable',
                2: 'forwarded',
                3: 'proxiable',
                4: 'proxy',
                5: 'allow-postdate',
                6: 'postdated',
                7: 'unused7',
                8: 'renewable',
                9: 'unused9',
                10: 'unused10',
                11: 'unused11',
                27: 'renewable-ok',
                28: 'enc-tkt-in-skey',
                30: 'renew',
                31: 'validate',
        }

class Checksum(Sequence):
        _fields = [
                        ('cksumtype', Integer, {'explicit': 0, 'optional': False}),
                        ('checksum', OctetString, {'explicit': 1, 'optional': False}),
        ]


class LastReqI(Sequence):
        _fields = [
                        ('lr-type', Integer, {'explicit': 0, 'optional': True}),
                        ('lr-value', KerberosTime, {'explicit': 1, 'optional': True}),
        ]


class LastReq(SequenceOf):
        _child_spec = LastReqI

class HostAddress(Sequence):
        _fields = [
                ('addr-type', Integer, {'explicit': 0, 'optional': True}),
                ('address', OctetString, {'explicit': 1, 'optional': True}),
]

class HostAddresses(SequenceOf):
        _child_spec = HostAddress

class NameString(SequenceOf):
        #tag = 2
        #method = 0
        _child_spec = GeneralString

class AuthorizationData(Sequence):
        _fields = [
                ('ad-type', Integer, {'explicit': 0, 'optional': True}),
                ('ad-data', OctetString, {'explicit': 1, 'optional': True}),
]

class AuthorizationDatas(SequenceOf):
        _child_spec = AuthorizationData

class PrincipalName(Sequence):        
        _fields = [
                ('name-type', Integer, {'explicit': 0, 'optional': False}),
                ('name-string', NameString, {'explicit': 1, 'optional': False}),
]

class EncryptedData(Sequence):
        _fields = [
                ('etype', Integer, {'explicit': 0, 'optional': False}),
                ('kvno', NameString, {'explicit': 1, 'optional': True}),
                ('cipher', OctetString, {'explicit': 1, 'optional': False}),
]

"""
class CipherText(Sequence):
        _fields = [
                        ('confounder', OctetString, {'explicit': 0, 'optional': True}),
                        ('check', OctetString, {'explicit': 1, 'optional': True}),
                        ('msg-seq', MsgSequence, {'explicit': 2, 'optional': False}), #??????????????????????????????????????????
                        ('pad', OctetString, {'explicit': 3, 'optional': True}),
        ]
"""

class EncPart(OctetString):
        method = 1
        tag    = 16

class EncryptionKey(Sequence):
        _fields = [
                        ('keytype', OctetString, {'explicit': 0, 'optional': False}),
                        ('keyvalue', OctetString, {'explicit': 1, 'optional': False}),
        ]

class TicketI(Sequence):
        _fields = [
                        ('tkt-vno', Integer, {'explicit': 0, 'optional': False}),
                        ('realm', Realm, {'explicit': 1, 'optional': False}),
                        ('sname', PrincipalName, {'explicit': 2, 'optional': False}),
                        ('enc-part', EncPart, {'explicit': 3, 'optional': False}), #EncryptedData
        ]

class Ticket(Sequence):
        class_ = 1
        tag    = 1
        
        _fields = [
                        ('ticket', TicketI),
        ]

class TransitedEncoding(Sequence):

        _fields = [
                        ('tr-type', Integer, {'explicit': 0, 'optional': False}),
                        ('contents', EncryptionKey, {'explicit': 1, 'optional': False}),
        ]

class EncTicketPart(Sequence):
        class_ = 1
        tag    = 3
        
        _fields = [
                        ('flags', TicketFlags, {'explicit': 0, 'optional': False}),
                        ('key', EncryptionKey, {'explicit': 1, 'optional': False}),
                        ('crealm', Realm, {'explicit': 2, 'optional': False}),
                        ('cname', PrincipalName, {'explicit': 3, 'optional': False}),
                        ('transited', TransitedEncoding, {'explicit': 4, 'optional': False}),
                        ('authtime', KerberosTime, {'explicit': 5, 'optional': False}),
                        ('starttime', KerberosTime, {'explicit': 6, 'optional': True}),
                        ('endtime', KerberosTime, {'explicit': 7, 'optional': False}),
                        ('renew-till', KerberosTime, {'explicit': 8, 'optional': True}),
                        ('caddr', HostAddresses, {'explicit': 9, 'optional': True}),
                        ('authorization-data', KerberosTime, {'explicit': 10, 'optional': True}),
        ]



class Authenticator(Sequence):
        class_ = 1
        tag    = 2

        _fields = [
                        ('authenticator-vno', Integer, {'explicit': 0, 'optional': False}),
                        ('crealm', Realm, {'explicit': 1, 'optional': False}),
                        ('cname', PrincipalName, {'explicit': 2, 'optional': False}),
                        ('cksum', Realm, {'explicit': 3, 'optional': True}),
                        ('cusec', Realm, {'explicit': 4, 'optional': False}),
                        ('ctime', KerberosTime, {'explicit': 5, 'optional': False}),
                        ('subkey', EncryptionKey, {'explicit': 6, 'optional': True}),
                        ('seq-number', Integer, {'explicit': 7, 'optional': True}),
                        ('authorization-data', AuthorizationDatas, {'explicit': 8, 'optional': True}),
        ]

class PA_DATA(Sequence):
        _fields = [
                        ('padata-type', Integer, {'explicit': 1, 'optional': False}),
                        ('padata-value', OctetString, {'explicit': 2, 'optional': False}),
        ]

class PA_DATAS(SequenceOf):
        _child_spec = PA_DATA

class Etype(SequenceOf):
        _child_spec = Integer

class AdditionalTickets(SequenceOf):
        _child_spec = Ticket

class KDC_REQ_BODY(Sequence):
        _fields = [
                        ('kdc-options', KDCOptions, {'explicit': 0, 'optional': False}),
                        ('cname', PrincipalName, {'explicit': 1, 'optional': True}),
                        ('realm', Realm, {'explicit': 2, 'optional': False}),
                        ('sname', PrincipalName, {'explicit': 3, 'optional': True}),
                        ('from', KerberosTime, {'explicit': 4, 'optional': True}),
                        ('till', KerberosTime, {'explicit': 5, 'optional': False}),
                        ('rtime', KerberosTime, {'explicit': 6, 'optional': True}),
                        ('nonce', Integer, {'explicit': 7, 'optional': False}),
                        ('etype', Etype, {'explicit': 8, 'optional': False}),
                        ('addresses', HostAddresses, {'explicit': 9, 'optional': True}),
                        ('enc-authorization-data', EncryptedData, {'explicit': 10, 'optional': True}),
                        ('additional-tickets', AdditionalTickets, {'explicit': 11, 'optional': True}),
        ]


class KDC_REQ(Sequence):
        _fields = [
                        ('pvno', Integer, {'explicit': 1, 'optional': False}),
                        ('msg-type', Integer, {'explicit': 2, 'optional': False}),
                        ('padata', PA_DATAS, {'explicit': 3, 'optional': True}),
                        ('req-body', KDC_REQ_BODY, {'explicit': 4, 'optional': False}),
        ]


class AS_REQ(Sequence):
        class_ = 1
        tag    = 10

        _fields = [
                        ('as-req', KDC_REQ),
        ]



class TGS_REQ(KDC_REQ):
        class_ = 1
        tag    = 12

        _fields = [
                        ('tgs-req', KDC_REQ),
        ]


class EncKDCRepPart(Sequence):
        _fields = [
                        ('key', EncryptionKey, {'explicit': 0, 'optional': False}),
                        ('last-req', LastReq, {'explicit': 1, 'optional': False}),
                        ('nonce', Integer, {'explicit': 2, 'optional': False}),
                        ('key-expiration', KerberosTime, {'explicit': 3, 'optional': True}),
                        ('flags', TicketFlags, {'explicit': 4, 'optional': False}),
                        ('authtime', KerberosTime, {'explicit': 5, 'optional': False}),
                        ('starttime', KerberosTime, {'explicit': 6, 'optional': True}),
                        ('endtime', KerberosTime, {'explicit': 7, 'optional': False}),
                        ('renew-till', KerberosTime, {'explicit': 8, 'optional': True}),
                        ('srealm', Realm, {'explicit': 9, 'optional': False}),
                        ('sname', PrincipalName, {'explicit': 10, 'optional': False}),
                        ('caddr', HostAddresses, {'explicit': 11, 'optional': True}),
        ]

class EncTGSRepPart(Sequence):
        class_ = 1
        tag    = 26

        _fields = [
                        ('as-req', EncKDCRepPart),
        ]

class EncASRepPart(Sequence):
        class_ = 1
        tag    = 25

        _fields = [
                        ('as-req', EncKDCRepPart),
        ]



class KDC_REP(Sequence):
        _fields = [
                        ('pvno', Integer, {'explicit': 0, 'optional': False}),
                        ('msg-type', Integer, {'explicit': 1, 'optional': False}),
                        ('padata', PA_DATAS, {'explicit': 2, 'optional': True}),
                        ('crealm', Realm, {'explicit': 3, 'optional': False}),
                        ('cname', PrincipalName, {'explicit': 4, 'optional': False}),
                        ('ticket', Ticket, {'explicit': 5, 'optional': False}),
                        ('enc-part', EncPart, {'explicit': 6, 'optional': False}), #EncryptedData

        ]

class AS_REP(Sequence):
        class_ = 1
        tag    = 11

        _fields = [
                        ('as-req', KDC_REP),
        ]

class TGS_REP(Sequence):
        class_ = 1
        tag    = 13

        _fields = [
                        ('as-req', KDC_REP),
        ]

class AP_REQ(Sequence):
        class_ = 1
        tag    = 14

        _fields = [
                        ('pvno', Integer, {'explicit': 0, 'optional': False}),
                        ('msg-type', Integer, {'explicit': 1, 'optional': False}),
                        ('ap-options', APOptions, {'explicit': 2, 'optional': False}),
                        ('ticket', Ticket, {'explicit': 3, 'optional': False}),
                        ('authenticator', EncryptedData, {'explicit': 4, 'optional': False}),
        ]

class AP_REP(Sequence):
        class_ = 1
        tag    = 15

        _fields = [
                        ('pvno', Integer, {'explicit': 0, 'optional': False}),
                        ('msg-type', Integer, {'explicit': 1, 'optional': False}),
                        ('enc-part', EncryptedData, {'explicit': 2, 'optional': False}),
        ]        

class EncAPRepPart(Sequence):
        class_ = 1
        tag    = 27

        _fields = [
                        ('ctime', KerberosTime, {'explicit': 0, 'optional': False}),
                        ('cusec', Integer, {'explicit': 1, 'optional': False}),
                        ('subkey', EncryptionKey, {'explicit': 2, 'optional': True}),
                        ('seq-number', Integer, {'explicit': 3, 'optional': True}),
        ]

class KRB_SAFE_BODY(Sequence):
        _fields = [
                        ('user-data', OctetString, {'explicit': 0, 'optional': False}),
                        ('timestamp', KerberosTime, {'explicit': 1, 'optional': True}),
                        ('usec', Integer, {'explicit': 2, 'optional': True}),
                        ('seq-number', Integer, {'explicit': 3, 'optional': True}),
                        ('s-address', HostAddress, {'explicit': 4, 'optional': False}),
                        ('r-address', HostAddress, {'explicit': 5, 'optional': True}),
        ]

class KRB_SAFE(Sequence):
        class_ = 1
        tag    = 20

        _fields = [
                        ('pvno', Integer, {'explicit': 0, 'optional': False}),
                        ('msg-type', Integer, {'explicit': 1, 'optional': False}),
                        ('safe-body', KRB_SAFE_BODY, {'explicit': 2, 'optional': False}),
                        ('cksum', Checksum, {'explicit': 3, 'optional': False}),
        ]




class EncKrbPrivPart(Sequence):
        class_ = 1
        tag    = 28

        _fields = [
                        ('user-data', OctetString, {'explicit': 0, 'optional': False}),
                        ('timestamp', KerberosTime, {'explicit': 1, 'optional': True}),
                        ('usec', Integer, {'explicit': 2, 'optional': True}),
                        ('seq-number', Integer, {'explicit': 3, 'optional': True}),
                        ('s-address', HostAddress, {'explicit': 4, 'optional': False}),
                        ('r-address', HostAddress, {'explicit': 5, 'optional': True}),
        ]


class KRB_PRIV(Sequence):
        class_ = 1
        tag    = 28

        _fields = [
                        ('pvno', Integer, {'explicit': 0, 'optional': False}),
                        ('msg-type', Integer, {'explicit': 1, 'optional': False}),
                        ('enc-part', EncryptedData, {'explicit': 3, 'optional': False}),
        ]

class KrbCredInfo(Sequence):
        _fields = [
                        ('key', EncryptionKey, {'explicit': 0, 'optional': False}),
                        ('prealm', Realm, {'explicit': 1, 'optional': True}),
                        ('pname', PrincipalName, {'explicit': 2, 'optional': True}),
                        ('flags', TicketFlags, {'explicit': 3, 'optional': True}),
                        ('authtime', KerberosTime, {'explicit': 4, 'optional': True}),
                        ('starttime', KerberosTime, {'explicit': 5, 'optional': True}),
                        ('endtime', KerberosTime, {'explicit': 6, 'optional': True}),
                        ('renew-till', KerberosTime, {'explicit': 7, 'optional': True}),
                        ('srealm', Realm, {'explicit': 8, 'optional': True}),
                        ('sname', PrincipalName, {'explicit': 9, 'optional': True}),
                        ('caddr', HostAddresses, {'explicit': 10, 'optional': True}),
        ]

class KrbCredInfos(SequenceOf):
        _child_spec = KrbCredInfo


class EncKrbCredPart(Sequence):
        class_ = 1
        tag    = 29

        _fields = [
                        ('ticket-info', KrbCredInfos, {'explicit': 0, 'optional': False}),
                        ('nonce', Integer, {'explicit': 1, 'optional': True}),
                        ('timestamp', KerberosTime, {'explicit': 2, 'optional': True}),
                        ('usec', Integer, {'explicit': 3, 'optional': True}),
                        ('s-address', HostAddress, {'explicit': 4, 'optional': True}),
                        ('r-address', HostAddress, {'explicit': 5, 'optional': True}),
        ]

class Tickets(SequenceOf):
        _child_spec = Ticket

class KRB_CRED(Sequence):
        class_ = 1
        tag    = 22

        _fields = [
                        ('pvno', Integer, {'explicit': 0, 'optional': False}),
                        ('msg-type', Integer, {'explicit': 1, 'optional': False}),
                        ('tickets', Tickets, {'explicit': 2, 'optional': False}),
                        ('enc-part', EncryptedData, {'explicit': 3, 'optional': False}),
        ]

class KRB_ERRORI(Sequence):
        _fields = [
                        ('pvno', Integer, {'explicit': 0, 'optional': False}),
                        ('msg-type', Integer, {'explicit': 1, 'optional': False}),
                        ('ctime', KerberosTime, {'explicit': 2, 'optional': True}),
                        ('cusec', Integer, {'explicit': 3, 'optional': True}),
                        ('stime', KerberosTime, {'explicit': 4, 'optional': False}),
                        ('susec', Integer, {'explicit': 5, 'optional': False}),
                        ('error-code', Integer, {'explicit': 6, 'optional': False}),
                        ('crealm', Realm, {'explicit': 7, 'optional': True}),
                        ('cname', PrincipalName, {'explicit': 8, 'optional': True}),
                        ('realm', Realm, {'explicit': 9, 'optional': False}),
                        ('sname', PrincipalName, {'explicit': 10, 'optional': False}),
                        ('e-text', GeneralString, {'explicit': 11, 'optional': True}),
                        ('e-data', OctetString, {'explicit': 12, 'optional': True}),
        ]

class KRB_ERROR(Sequence):
        class_ = 1
        tag    = 30

        _fields = [
                        ('krberr', KRB_ERRORI),
        ]


