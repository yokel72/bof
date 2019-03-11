#!/usr/bin/env python

import socket, argparse, time

parser = argparse.ArgumentParser()
parser.add_argument("RHOST", help="Remote host IP")
parser.add_argument("RPORT", help="Remote host port", type=int)
parser.add_argument("-l", help="Max number of bytes to send; default 1000", type=int, default=1000, dest='max_num_bytes')

args = parser.parse_args()

for i in range(100, args.max_num_bytes+1, 100):
    buf = "A" * i
    print "Fuzzing service with %s bytes" % i

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((args.RHOST, args.RPORT))

        s.send(buf + '\n')
        s.recv(1024)
        s.close()

        time.sleep(0.5)

    except:
        print "Error connecting to service..."
        if len(buf) > 100:
            print "Crash occurred with buffer length: " + str(len(buf))
        exit()
