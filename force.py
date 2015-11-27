#!/usr/bin/env python

import pwd
import requests
import sys
import syslog
import os
import subprocess


allowedtries = 3
verifyfunction = lambda x: x.isalnum()

me = os.getlogin()
url = None
excluded = []

syslog.openlog("verify2fa")

def allow():
    cmd = "/bin/bash -l"

    if os.environ.has_key("SSH_ORIGINAL_COMMAND"):
        cmd = os.environ['SSH_ORIGINAL_COMMAND']
    ret = os.system(cmd)
    sys.exit( ret )
   


for p in sys.argv[1:]:
    if p[:4] == "url=":
        url = p[4:]
    if p[:8] == "exclude=":
        for q in p[8:].split(","):
            excluded.append(q)
   
if me in excluded:
    syslog.syslog("Skipping 2FA because %s is excluded." % me)
    allow()


if not url:
    syslog.syslog("No URL given for verification, bailing out.")
    sys.exit(1)



tried = 0

while tried < allowedtries:
    print "Please enter your second factor: "
    factor = sys.stdin.readline().strip()
    tried += 1
    
    if not factor:
        print "No factor given, please retry.\n"
        continue

    if not verifyfunction(factor):
        print "Factor contains illegal characters, please retry.\n"
        continue

    useurl = url.replace('%USER%',me).replace('%FACTOR%', factor)

    r = requests.get(useurl)

    if r.status_code == 200:
        print "Success, logging you in."
        syslog.syslog("Allowed %s after successfull verification." % me)
        allow()
    else:
        print "Verification failed, please try again."


syslog.syslog("Failing %s after too many tries." % me)
print "Too many failures, bailing out.\n"

sys.exit(1)


