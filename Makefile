PWD = $(shell pwd)

.PHONY:
	module

default: module user util gen

module:
	make -C $(PWD)/hp-mod

util:
	make -C $(PWD)/util

gen:
	make -C $(PWD)/pkt_gen

user:
	make -C $(PWD)/hp-user

clean_mod:
	make -C $(PWD)/hp-mod clean

clean_user:
	make -C $(PWD)/hp-user clean

clean_gen:
	make -C $(PWD)/pkt_gen clean

clean: clean_mod clean_user clean_gen
