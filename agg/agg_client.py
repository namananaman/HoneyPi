#!/usr/bin/env python
import argparse
import fcntl
import os
import socket
import sys

def parse_args():
    parser = argparse.ArgumentParser(description='Send honeypot results to an aggregation server.')
    parser.add_argument('--host', dest='host', default='127.0.0.1',
                        help='Server IP to connect to')
    parser.add_argument('--port', dest='port', type=int, default=5413,
                        help='Server port to connect on')
    parser.add_argument('--file', dest='fname', default=None,
                        help='Filename to read from (stdin used by default)')
    args = parser.parse_args()
    return args


def setup_input(fname):
    if not fname:
        f = sys.stdin
    else:
        f = open(fname, 'r')
    # fd = f.fileno()
    # fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    # fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    return f


# def readlines(f):
#     try:
#         return f.readlines()
#     except IOError:
#         return []


def send(skt, message):
    skt.send(message.encode('utf-8'))


def sendmsg(f_in, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    for line in f.readlines():
        # May not give \n on the line, but we NEED it for the server. This
        # ensures that it's present
        fixed_l = line.split('\n', 1)[0] + '\n'
        send(s, fixed_l)

    s.close()


if __name__ == "__main__":
    args = parse_args()
    f = setup_input(args.fname)
    sendmsg(f, args.host, args.port)