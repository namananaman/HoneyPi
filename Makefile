PWD = $(shell pwd)

.PHONY:
	module

default: module user

module:
	make -C $(PWD)/hp-mod

user:
	make -C $(PWD)/hp-user

clean_mod:
	make -C $(PWD)/hp-mod clean


clean: clean_mod
