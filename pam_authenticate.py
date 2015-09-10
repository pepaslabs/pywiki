#!/usr/bin/python

# pam_authenticate.py: a script to check a user's password against PAM.
# part of the pywiki project, see https://github.com/pepaslabs/pywiki
# written by jason pepas, released under the terms of the MIT license.

# usage: pipe a password into this script, giving the username as the first argument.
# a zero exit status indicates successful authentication.

import sys
import pam # debian users: apt-get install python-pampy

logged_in = False

try:
    user = sys.argv[1]
    passwd = sys.stdin.read()
    logged_in = pam.authenticate(user, passwd)
except Exception as e:
    sys.exit(2)
else:
    if logged_in == True:
        sys.exit(0)
    else:
        sys.exit(1)
