import datetime
from responder3.protocols.NTP import *

epoch = datetime.datetime(1900, 1, 1)

test = epoch + datetime.timedelta(seconds= 2208988800.0000001)

print(test.isoformat())

t = datetime.datetime.now() - epoch
print(t.total_seconds())


now = datetime.datetime.now()
ab = NTPTimeStamp.fromDatetime(now)
ca = ab.toDatetime()
print(now)
print(ca)

data = bytes.fromhex('230306eb000003400000038bc3828412de2944aa89f559bede29456a1e76be5ade29456a20333a01de2945ae1cced543')
a = NTPPacket.from_bytes(data)
print(repr(a))

print(a.toBytes().hex())
print(data.hex())
assert a.toBytes() == data 

#ntpdate -q 127.0.0.1