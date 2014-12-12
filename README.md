HoneyPi
=======

A distributed network honeypot that runs on Raspberry Pis


Building
========

type make in the toplevel directory

This will build the kernel module, userspace program, and packet generator. Alternatively you can type make in each of hp-mod, hp-user, and pkt\_gen

Running
=======

On each host run setup\_network.sh. This will make sure the buffers are of sufficient size.

Make sure the config file 'hp-user/honeypi.config' has the correct IP address, the address
and ports of the pi must be in the first lines and the address and port of the aggregator
server must be in the last line. The config file we used is in the repository.

On the switch make sure IP routing is enabled and run in the config terminal

  `ip route add 192.168.2.0/26 192.168.2.4`
  `ip route add 192.168.2.64/26 192.168.2.3`
  `ip route add 192.168.2.128/26 192.168.2.4`
  `ip route add 192.168.2.192/26 192.168.2.3`

On the aggregation server

  ./agg\_server.py

On each worker node:

  run 'insmod hp-mod/honeypi.ko' This requires root privileges. This is the
  kernel module which hashes and buffer the induvidual packet statistics.

  You need to find out what the major number of the module is, this can
  be done by running 'cat /proc/devices' and finding the entry for honeypi.

  Once you have the major number. Run:

    mknod /dev/honeypi c "major\_number"

  This creates the device file.

  Finally run

  ./honeypi\_read as root. You must be in the same directory as "honeypi.config"

On the packet generator host:

  run ./pkt\_gen <mbps> 192.168.1.0 0 1
