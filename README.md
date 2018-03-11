# IMPORTANT NOTICE
This project is not ready to be used in production yet!  
## Posioner status  
All of the poisoner modules are working well, except for DHCP which is is still coughing.  
## Server status 
The Genericproxy is stable  
HTTP now supports BASIC and NTLM cred stealing and can work as an actual proxy (SSL interception and invisible proxy is still under developement)  
NTP is okay you can spoof system time with it (combining with DHCP) however the packet parsing is limited to the header, no extensions yet.  

## Client status
yes.  

# Responder3
New and improved Responder for Python3


## Installation
It is preferred to install Responder3 using the "setup.py install" method. However actual installation is not needed, you can use it simply by cloning this project from this repo then edit config.py to suit your needs and execute Responder3.py. 
Prerequisites must be installed first of cource.

## Prerequisites
* Python3.6 or above
* python3-pip
* setupttols
* asn1crypto
* oscrypto
* certbuilder

### Ubuntu 14.04, 16.04, 16.10 or 17.04
If you are using older version first you must install python3.6 and preferably pip3.6.  
Some help on these links:  
[DigitalOcean](https://www.digitalocean.com/community/tutorials/how-to-install-python-3-and-set-up-a-local-programming-environment-on-ubuntu-16-04)  
[Askubuntu](https://askubuntu.com/questions/865554/how-do-i-install-python-3-6-using-apt-get)  
After installing python3.6 and pip3.6 you may proceed with the steps below in (Ubuntu >= 17.10)

### Ubuntu >= 17.10
For  python3 is already at version 3.6 so you can skip this step.  
```
apt -y install git python3-setuptools python3-pip
pip3 install asn1crypto oscrypto certbuilder
git clone https://github.com/skelsec/Responder3.git
cd Responder3
python3 setup.py install
```

### Kali
Same as Ubuntu >= 17.10

### Windows
Download and install python3.6 (the full version, not a protable one)  
Download or clone Responder3 from this repo  
If you have internet access then just install Responder3 with ```python3 setup.py install```  
Otherwise you'll need to first download and install the prerequisites manually in the following order:  
* setupttols
* asn1crypto
* certbuilder
Then you can install Responder3 with the forementioned command.

### OSX
You are on your own until someone who has a Mac writes a howto for you.
(PRs are welcome)
