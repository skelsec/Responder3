# IMPORTANT NOTICE
This project is not ready to be used in production yet!  
Also, this project has a [WIKI](https://github.com/skelsec/Responder3/wiki)  
## Posioner status  
All of the poisoner modules are working well, except for DHCP which is is still coughing.  

## Server status 
| Server      |  AUTH TYPE   | Status  |
|-------------|:-------------:|-----:|
|FTP|PLAIN|OK|
|HTTP|BASIC|OK|
|HTTP|NTLM|OK|
|HTTP Proxy|PLAIN|OK|
|HTTP Proxy|PLAIN|OK|
|IMAP|PLAIN|OK|
|IMAP|AUTH|NA|
|Kerberosv5|krb5pa|OK|
|LDAP|PLAIN|OK|
|LDAP|SASL - PLAIN|OK|
|LDAP|NTLM|OK|
|MYSQL|PLAIN|OK|
|MYSQL|CRAM - SHA1|OK|
|POP3|PLAIN|OK|
|POP3|AUTH|OK|
|POP3|APOP|OK|
|RLOGIN|NA|OK|
|SMTP|PLAIN|OK|
|SMTP|LOGIN|OK|
|SOCKS5|PLAIN|OK|
|SSH|PLAIN|OK|
|TELNET|PLAIN|OK|
|VNC|DES|OK|
|VNC|NA|OK|

## Client status
yes.

# Responder3
New and improved Responder for Python3


## Installation
It is preferred to install Responder3 using the "setup.py install" method. However actual installation is not needed, you can use it simply by cloning this project from this repo then edit config.py to suit your needs and execute Responder3.py. 
Prerequisites must be installed first of cource.

```
pip3.7 install -r requirements.txt
git clone https://github.com/skelsec/Responder3.git
cd Responder3
python3.7 setup.py install
```

## Prerequisites
* Python3.7 or above
* pip
* setupttols
* asn1crypto
* oscrypto
* certbuilder
* websockets
* rsa
* bson
