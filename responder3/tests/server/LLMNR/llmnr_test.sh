#!/usr/bin/env bash

#only works with sudo, and sometimes nmap segfaults without doing the actual resolution
sudo nmap --script llmnr-resolve --script-args 'llmnr-resolve.hostname=alma.com'