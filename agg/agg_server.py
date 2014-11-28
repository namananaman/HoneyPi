#!/usr/bin/env python
import argparse
import socket
import signal
import sys
from datetime import datetime
from threading import Thread, Lock


NUM_WORKERS = 16
spammers  = dict()
spam_lock = Lock()
ports     = dict()
port_lock = Lock()
evil      = dict()
evil_lock = Lock()
protocols = dict()
pcls_lock = Lock()


class ClientHandler(Thread):

    def __init__(self, skt, skt_lock):
        Thread.__init__(self)
        self.skt = skt
        self.lock = skt_lock

    def readlines(self):
        # untested
        buf = self.client.recv(4096)
        done = False
        while not done:
            if "\n" in buf:
                (line, buf) = buf.split("\n", 1)
                yield line #+"\n"
            else:
                more = self.client.recv(4096)
                if not more:
                    done = True
                else:
                    buf = buf+more
        if buf:
            yield buf

    def aggregate(self):
        current_dict = None
        current_lock = None
        for line in self.readlines():
            if "Spammers" in line:
                current_dict = spammers
                current_lock = spam_lock
                continue
            elif "Ports" in line:
                current_dict = ports
                current_lock = port_lock
                continue
            elif "Evil" in line:
                current_dict = evil
                current_lock = evil_lock
                continue
            elif "Protocols" in line:
                current_dict = protocols
                current_lock = pcls_lock
                continue
            elif "Begin" in line or "End" in line:
                continue

            if not current_lock:
                continue
            try:
                key, value = line.split(':', 1)
                value = int(value)
            except ValueError:
                continue

            with current_lock:
                if key in current_dict:
                    current_dict[key] += value
                else:
                    current_dict[key] = value

    def run(self):
        while True:
            with self.lock:
                (client, address) = self.skt.accept()
                self.client = client
            self.aggregate()


def parse_args():
    parser = argparse.ArgumentParser(description='Aggregate honeypot results from clients.')
    parser.add_argument('--host', dest='host', default='0.0.0.0',
                        help='Server IP to bind to')
    parser.add_argument('--port', dest='port', type=int, default=5413,
                        help='Server port to listen on')
    parser.add_argument('--file', dest='fname', default=None,
                        help='Filename to write results to (stdout used by default)')
    args = parser.parse_args()
    return args


def setup_skt(host, port):
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    skt.bind((host, port))
    skt.listen(5)
    return skt


def start_threads(skt):
    skt_lock = Lock()
    for i in range(NUM_WORKERS):
        new_t = ClientHandler(skt, skt_lock)
        new_t.start()


def write_output(signal, frame):
    global out_f
    out_f.write("\n==============================================\n")
    out_f.write("HONEYPOT STATISTICS @ %s\n" % str(datetime.now()))
    out_f.write("\nSPAMMERS:\n")
    for key in spammers:
        out_f.write('%s: %d\n' % (key, spammers[key]))
    out_f.write("\nPORTS:\n")
    for key in ports:
        out_f.write('%s: %d\n' % (key, ports[key]))
    out_f.write("\nEVIL PACKETS:\n")
    for key in evil:
        out_f.write('%s: %d\n' % (key, evil[key]))
    out_f.write("\nPROTOCOLS:\n")
    for key in protocols:
        out_f.write('%s: %d\n' % (key, protocols[key]))
    out_f.write("\nEND OF STATISTICS")
    out_f.write("\n==============================================\n")


if __name__ == "__main__":
    global out_f
    args = parse_args()
    if args.fname:
        out_f = open(args.fname, 'w')
    else:
        out_f = sys.stdout
    server_skt = setup_skt(args.host, args.port)
    start_threads(server_skt)
    signal.signal(signal.SIGINT, write_output)
    while True:
        signal.pause()
