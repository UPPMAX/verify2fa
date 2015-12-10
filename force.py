#!/usr/bin/env python

import pwd
import requests
import sys
import syslog
import os
import subprocess
import time


gracetime = 10
allowedtries = 3
verifyfunction = lambda x: x.isalnum()

me = os.getlogin()
url = None
excluded = []
gracename = None

remote = None

try:
    remote = os.environ['SSH_CLIENT']
    remote = remote[:remote.index(' ')]
except:
    pass

try:
    gracename = os.path.join(os.environ['HOME'], '.gracetimefile')
except: 
    pass


syslog.openlog("verify2fa")

def allow():

    try:
        if gracename:

            f = open(gracename, 'w')
            f.write("%s %f\n" % (remote, time.time()))
            f.close()

    except:
        pass

    cmd = "/bin/bash -l"

    if os.environ.has_key("SSH_ORIGINAL_COMMAND"):
        cmd = os.environ['SSH_ORIGINAL_COMMAND']
    ret = os.system(cmd)
    sys.exit( ret )
   


for p in sys.argv[1:]:
    if p[:6] == "--url=":
        url = p[6:]
    if p[:10] == "--exclude=":
        for q in p[10:].split(","):
            excluded.append(q)
    if p[:11] == "--maxtries=":
        allowedtries=int(p[11:])
    if p[:12] == "--gracetime=":
        gracetime=int(p[12:])


   
if me in excluded:
    syslog.syslog("Skipping 2FA because %s is excluded." % me)
    allow()


if not url:
    syslog.syslog("No URL given for verification, bailing out.")
    sys.exit(1)

# Check if we're within gracetime.
try:
    if gracename:
        s = os.stat(gracename)
        # Check time of file
        if time.time()-s.st_mtime < gracetime*60:
            line = open(gracename, 'r').read()
            l = line.index(' ')
            if line[:l] == remote and time.time()-float(line[l:]) < gracetime*60:
                allow()
except:
    pass

tried = 0

while tried < allowedtries:
    print "Please enter your second factor: "
    factor = None

    while not factor:
      time.sleep(0.2)
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


