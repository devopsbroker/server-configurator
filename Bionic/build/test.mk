#
# test.mk - DevOpsBroker makefile for creating a .tar.xz archive of Ubuntu 18.04 Desktop Configurator
#
# Copyright (C) 2018 Edward Smith <edwardsmith@devopsbroker.org>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------------
# Developed on Ubuntu 18.04.1 LTS running kernel.osrelease = 4.15.0-38
#
# This makefile builds a tar.xz archive that can be used for testing the
# install process and functionality of configure-desktop without having to
# mess with installing/uninstalling a .deb package.
# -----------------------------------------------------------------------------
#

################################### Includes ##################################

include /etc/devops/globals.mk

################################## Variables ##################################

PKG_NAME := desktop-configurator
VERSION := 2.0.0
ARCH := amd64
PKG_ARCHIVE := $(PKG_NAME)_$(VERSION)_$(ARCH)

BUILD_DIR := $(TMPDIR)/$(PKG_ARCHIVE)
APPLICATION_DIR = $(realpath $(CURDIR)/..)
UTILITIES_DIR = $(realpath $(CURDIR)/../../../Utilities)
RELEASE_DIR := $(CURDIR)/tar-test

EXEC_CP := /bin/cp --preserve=timestamps

################################### Targets ###################################

.ONESHELL:
.PHONY: default clean makeutils createdirs copybase copydoc copyetc copyhome \
	copyperf copyusr tar printenv

default: tar

clean:
	echo
	$(call printInfo,Cleaning existing test artifacts)
	/bin/rm -rf $(BUILD_DIR)
	/bin/rm -f $(TMPDIR)/$(PKG_ARCHIVE).tar.xz
	/bin/rm -rf $(RELEASE_DIR)

makeutils:
	echo
	$(call printInfo,Making C language utility binaries)
	$(MAKE) TMPDIR=$(TMPDIR) --directory=$(UTILITIES_DIR)/C clean
	$(MAKE) TMPDIR=$(TMPDIR) --directory=$(UTILITIES_DIR)/C install

createdirs: clean
	echo
	$(call printInfo,Creating $(RELEASE_DIR) directory)
	/bin/mkdir -p --mode=0750 $(RELEASE_DIR)

	$(call printInfo,Creating $(BUILD_DIR) directory)
	/bin/mkdir -p --mode=0755 $(BUILD_DIR)

	$(call printInfo,Creating $(BUILD_DIR)/archives directory)
	/bin/mkdir -p $(BUILD_DIR)/archives

copybase: createdirs
	$(call printInfo,Copying configure-desktop.sh to $(BUILD_DIR))
	$(EXEC_CP) $(APPLICATION_DIR)/configure-desktop.sh $(BUILD_DIR)

	$(call printInfo,Copying device-drivers.sh to $(BUILD_DIR))
	$(EXEC_CP) $(APPLICATION_DIR)/device-drivers.sh $(BUILD_DIR)

	$(call printInfo,Copying install.sh to $(BUILD_DIR))
	$(EXEC_CP) $(APPLICATION_DIR)/install.sh $(BUILD_DIR)

	$(call printInfo,Copying ttf-msclearfonts.sh to $(BUILD_DIR))
	$(EXEC_CP) $(APPLICATION_DIR)/ttf-msclearfonts.sh $(BUILD_DIR)

	$(call printInfo,Copying update-utils.sh to $(BUILD_DIR))
	$(EXEC_CP) $(APPLICATION_DIR)/update-utils.sh $(BUILD_DIR)

	$(call printInfo,Copying archives/tidy-5.6.0-64bit.deb to $(BUILD_DIR)/archives)
	$(EXEC_CP) $(APPLICATION_DIR)/archives/tidy-5.6.0-64bit.deb $(BUILD_DIR)/archives

copydoc: createdirs
	$(call printInfo,Copying doc/ files to $(BUILD_DIR)/doc)
	$(EXEC_CP) -r $(APPLICATION_DIR)/doc $(BUILD_DIR)

copyetc: createdirs
	$(call printInfo,Copying etc/ files to $(BUILD_DIR)/etc)
	$(EXEC_CP) -r $(APPLICATION_DIR)/etc $(BUILD_DIR)

copyhome: createdirs
	$(call printInfo,Copying home/ files to $(BUILD_DIR)/home)
	$(EXEC_CP) -r $(APPLICATION_DIR)/home $(BUILD_DIR)

copyperf: createdirs
	$(call printInfo,Copying perf/ files to $(BUILD_DIR)/perf)
	$(EXEC_CP) -r $(APPLICATION_DIR)/perf $(BUILD_DIR)

copyusr: createdirs
	$(call printInfo,Copying usr/ files to $(BUILD_DIR)/usr)
	$(EXEC_CP) -r $(APPLICATION_DIR)/usr $(BUILD_DIR)

tar: copybase copydoc copyetc copyhome copyperf copyusr
	echo
	$(call printInfo,Building $(PKG_ARCHIVE).tar.xz)
	/bin/tar cJvf $(RELEASE_DIR)/$(PKG_ARCHIVE).tar.xz --directory $(TMPDIR) $(PKG_ARCHIVE)

	echo
	$(call printInfo,Generating SHA256SUM and fileinfo.html)
	cd $(RELEASE_DIR) && \
	/usr/bin/sha256sum $(PKG_ARCHIVE).tar.xz > SHA256SUM && \
	/usr/local/bin/venture fileinfo $(PKG_ARCHIVE).tar.xz

	/bin/rm -rf $(BUILD_DIR)

printenv:
	echo "  MAKEFILE_LIST: $(MAKEFILE_LIST)"
	echo "         TMPDIR: $(TMPDIR)"
	echo "         CURDIR: $(CURDIR)"
	echo "       PKG_NAME: $(PKG_NAME)"
	echo "        VERSION: $(VERSION)"
	echo "           ARCH: $(ARCH)"
	echo "    PKG_ARCHIVE: $(PKG_ARCHIVE)"
	echo "      BUILD_DIR: $(BUILD_DIR)"
	echo "APPLICATION_DIR: $(APPLICATION_DIR)"
	echo "  UTILITIES_DIR: $(UTILITIES_DIR)"
	echo "    RELEASE_DIR: $(RELEASE_DIR)"
	echo
