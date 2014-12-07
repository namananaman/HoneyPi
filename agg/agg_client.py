#!/usr/bin/env python
import argparse
import fcntl
import os
import signal
import socket
import sys

def parse_args():
    parser = argparse.ArgumentParser(description='Send honeypot results to an aggregation server.')
    parser.add_argument('--host', dest='host', default='127.0.0.1',
                        help='Server IP to connect to')
    parser.add_argument('--port', dest='port', type=int, default=5413,
                        help='Server port to connect on')
    parser.add_argument('-f', '--file', dest='fname', default=None,
                        help='Filename to read from (stdin used by default)')
    args = parser.parse_args()
    return args


def setup_input(fname):
    if not fname:
        f = sys.stdin
    else:
        f = open(fname, 'r')
    fd = f.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    return f


def readlines(f):
    try:
        return f.readlines()
    except IOError:
        return []


def send(skt, message):
    skt.send(message.encode('utf-8'))


def sendmsg(f_in, host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    more_lines = True
    while more_lines:
        more_lines = False
        for line in readlines(f_in):
            more_lines = True  # only hit if there was at least one line to handle
            # May not give \n on the line, but we NEED it for the server. This
            # ensures that it's present
            fixed_l = line.split('\n', 1)[0] + '\n'
            send(s, fixed_l)

    s.close()


def send_clr_stats(host, port):
    # Clears client statistics in the server, i.e. don't compare
    # new statistics to the old one again
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    send(s, "CLEAR_STATISTICS\n")


def send_input(signal, frame):
    print "Sending statistics."
    sendmsg(f, host, port)


if __name__ == "__main__":
    args = parse_args()
    host = args.host
    port = args.port
    f = setup_input(args.fname)
    send_clr_stats(host, port)
    # sendmsg(f, host, port)
    signal.signal(signal.SIGINT, send_input)
    while True:
        signal.pause()