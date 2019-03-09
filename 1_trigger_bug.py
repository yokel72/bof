#!/usr/bin/env python

import socket, argparse

parser = argparse.ArgumentParser()
parser.add_argument("RHOST", help="Remote host IP")
parser.add_argument("RPORT", help="Remote host port", type=int)
parser.add_argument("-l", help="Max buffer length in bytes; default 1024", type=int, default=1024, dest='buf_len')

args = parser.parse_args()

buf = "A" * args.buf_len + "\n"

print buf

print "Attempting to connect to service..."

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((args.RHOST, args.RPORT))

    print "Sending %s A's..." % args.buf_len
    s.send(buf)

    print "%s A's sent." % args.buf_len

except:
    print "Error connecting to service..."
