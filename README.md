HoneyPi
=======

A distributed network honeypot that runs on Raspberry Pis.


Building
========

type make in the toplevel directory, but it's unlikely you'll want to build everything on one host.

This will build the kernel module, userspace program, and packet generator. Alternatively you can type make in each of hp-mod, hp-user, and pkt\_gen for each piece that you want.


Running
=======

On each host run `sudo setup\_network.sh`. This will make sure the UDP buffers are of sufficient size.

Make sure the config file 'hp-user/honeypi.config' has the correct IP address, the address
and ports of the pi must be in the first lines and the address and port of the aggregator
server must be in the last line. The config file we used is in the repository.

On the switch make sure IP routing is enabled and run in the config terminal

  `ip route add 192.168.2.0/26 192.168.2.4`
  `ip route add 192.168.2.64/26 192.168.2.3`
  `ip route add 192.168.2.128/26 192.168.2.4`
  `ip route add 192.168.2.192/26 192.168.2.3`

And check the routes with `show ip route`.

On the aggregation server

  ./agg\_server.py

This must be started before honeypi\_read.

On each worker node:

  run 'insmod hp-mod/honeypi.ko' This requires root privileges. This is the
  kernel module which hashes and buffer the induvidual packet statistics.

  You need to find out what the major number of the module is, this can
  be done by running 'cat /proc/devices' and finding the entry for honeypi.

  Once you have the major number. Run:

    mknod /dev/honeypi c "major\_number"

  This creates the device file. Generally this'll be `mknod /dev/honeypi c 248 0`.

  Finally run

  ./honeypi\_read as root. You must be in the same directory as "honeypi.config"

On the packet generator host:

  run ./pkt\_gen <mbps> 192.168.1.0 0 1

Alternatively, run `./pkt\_gen <mbps> <specific\_ip> 0` to send to a specific host.


What are all these folders?
===========================

agg: contains aggregator server. agg\_client.py was used previously
     but is deprecated (honeypi\_read sends messages directly)
hp-mod: Kernel module.
hp-user: Userspace program to read from kernel module.
pkt\_gen: packet generator
everything else: expendable

