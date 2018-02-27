import enum
import binascii
import datetime
import sys

def wintime2datetime(timeint):
        return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=(timeint/ 10.))

def dt2wt(dt):
        return int(dt.timestamp() * 10000000.0)