#!/bin/bash

sysctl -w net.core.rmem_max=8388608
sysctl -w net.core.wmem_max=8388608
sysctl -w net.core.rmem_default=65536
sysctl -w net.core.wmem_default=65536
sysctl -w net.core.udp_rmem_min=65536
sysctl -w net.core.udp_wmem_min=65536
sysctl -w net.core.udp_mem='8388608 8388608 8388608'
sysctl -w net.ipv4.route.flush=1