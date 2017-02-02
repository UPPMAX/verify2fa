#!/usr/bin/env python
#
# This file comes from puppet.
#

import pwd
import requests
import sys
import syslog
import os
import stat
import subprocess
import time
import pwd

gracetime = 10
allowedtries = 3
verifyfunction = lambda x: x.isalnum()

me =  pwd.getpwuid(os.geteuid()).pw_name
url = None
newtokenurl = None
excluded = []
gracename = None
homedir = None

broker = None
remote = None

extraoutput = None

try:
    remote = os.environ['SSH_CLIENT']
    remote = remote[:remote.index(' ')]
except:
    pass

try:
    homedir = pwd.getpwuid(os.geteuid()).pw_dir
    os.environ['HOME'] = homedir
except:
    pass

try:
    gracename = os.path.join(homedir, '.gracetimefile')      
except: 
    pass

syslog.openlog("verify2fa")

def allow(excluded=False):

    try:
        if gracename:

            f = open(gracename, 'w')
            f.write("%s %f\n" % (remote, time.time()))
            f.close()

    except:
        pass

    if excluded and broker:
        # Run broker instead and let that one launch
        os.execvp(broker,(broker,))
    else:
        cmd = "/bin/bash -l"

        if os.environ.has_key("SSH_ORIGINAL_COMMAND"):
            cmd = os.environ['SSH_ORIGINAL_COMMAND']
        ret = os.system(cmd)
        sys.exit( ret )

    # We should not be here
    sys.exit(1)
   


for p in sys.argv[1:]:
    if p[:6] == "--url=":
        url = p[6:]
    if p[:14] == "--newtokenurl=":
        newtokenurl = p[14:]
    if p[:9] == "--broker=":
        broker = p[9:]
    if p[:10] == "--exclude=":
        for q in p[10:].split(","):
            excluded.append(q)
    if p[:11] == "--maxtries=":
        allowedtries=int(p[11:])
    if p[:12] == "--gracetime=":
        gracetime=int(p[12:])
    if p[:15] == "--extra-output=":
        try:
            # Only care about files
            tocheck = p[15:].strip()
            
            if stat.S_ISREG(os.stat(tocheck).st_mode):
                extraoutput = tocheck
            
        except:
            pass


   
if me in excluded:
    syslog.syslog("Skipping 2FA because %s is excluded." % me)
    allow(True)


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
except SystemExit as e:
    raise e
except:
    pass

tried = 0

while tried < allowedtries:
    
    if extraoutput:
        try:
            # Do not clobber the screen, send at most 16 Kbytes.
            f = open(extraoutput, 'r')
            sys.stdout.write(f.read(16384))
            f.close()
        except:
            pass

    if newtokenurl:
        print
        print "If you do not have a second factor, you can request one at"
        print "%s" % newtokenurl
        print

    print "Please enter the current code from your second factor: "


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


