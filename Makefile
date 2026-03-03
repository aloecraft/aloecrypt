ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
__TECHNO_PROJECT_FILE:=.technoproj

-include script/version.mk
-include script/cargo_rs.mk

echo:
	@echo ${__VERSION}