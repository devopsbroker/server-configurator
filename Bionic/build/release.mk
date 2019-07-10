#
# release.mk - DevOpsBroker makefile for creating a .deb package of Ubuntu 18.04 Server Configurator
#
# Copyright (C) 2019 Edward Smith <edwardsmith@devopsbroker.org>
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
# Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-25
#
# -----------------------------------------------------------------------------
#

################################### Includes ##################################

include /etc/devops/globals.mk

################################## Variables ##################################

PKG_NAME := server-configurator
VERSION := 1.0.0
ARCH := amd64
PKG_ARCHIVE := $(PKG_NAME)_$(VERSION)_$(ARCH)

BUILD_DIR := $(TMPDIR)/$(PKG_ARCHIVE)
APPLICATION_DIR = $(realpath $(CURDIR)/..)
RELEASE_DIR := $(CURDIR)/pkg-debian

INSTALL_DIR := /opt/devopsbroker/bionic/server/configurator

EXEC_CP := /bin/cp --preserve=timestamps

################################### Targets ###################################

.ONESHELL:
.PHONY: default clean createdirs copyfiles copybase copyetc copyhome copyperf \
	copyusr configdocs installutils applysecurity package printenv

default: package

clean:
	echo
	$(call printInfo,Cleaning existing release artifacts)
	/bin/rm -rf $(BUILD_DIR)
	/bin/rm -f $(TMPDIR)/$(PKG_ARCHIVE).deb
	/bin/rm -rf $(RELEASE_DIR)

createdirs: clean
	echo
	$(call printInfo,Creating $(RELEASE_DIR) directory)
	/bin/mkdir -p --mode=0750 $(RELEASE_DIR)

	$(call printInfo,Creating $(BUILD_DIR) directory)
	/bin/mkdir -p --mode=0755 $(BUILD_DIR)

	$(call printInfo,Creating $(BUILD_DIR)/DEBIAN directory)
	/bin/mkdir -p --mode=0755 $(BUILD_DIR)/DEBIAN

	$(call printInfo,Creating /etc directory)
	/bin/mkdir -p --mode=0755 $(BUILD_DIR)/etc

	$(call printInfo,Creating /usr/share directory)
	/bin/mkdir -p --mode=0755 $(BUILD_DIR)/usr/share

	$(call printInfo,Creating $(INSTALL_DIR) directory)
	/bin/mkdir -p $(BUILD_DIR)/$(INSTALL_DIR)

	$(call printInfo,Setting directory permissions to 2750 and ownership to root:devops)
	/bin/chmod -R 2750 $(BUILD_DIR)/opt/devopsbroker
	/bin/chmod 0755 $(BUILD_DIR)/opt
	/bin/chown -R root:devops $(BUILD_DIR)/opt/devopsbroker
	echo

copybase: createdirs
	$(call printInfo,Copying configure-server.sh to $(INSTALL_DIR))
	$(EXEC_CP) $(APPLICATION_DIR)/configure-server.sh $(BUILD_DIR)/$(INSTALL_DIR)

copyetc: createdirs
	$(call printInfo,Copying etc/ files to $(INSTALL_DIR)/etc)
	$(EXEC_CP) -r $(APPLICATION_DIR)/etc $(BUILD_DIR)/$(INSTALL_DIR)

	$(call printInfo,Installing /etc/devops directory)
	/bin/mv $(BUILD_DIR)/$(INSTALL_DIR)/etc/devops $(BUILD_DIR)/etc

copyhome: createdirs
	$(call printInfo,Copying home/ files to $(INSTALL_DIR)/home)
	$(EXEC_CP) -r $(APPLICATION_DIR)/home $(BUILD_DIR)/$(INSTALL_DIR)

copyservices: createdirs
	$(call printInfo,Copying services/ files to $(INSTALL_DIR)/services)
	$(EXEC_CP) -r $(APPLICATION_DIR)/services $(BUILD_DIR)/$(INSTALL_DIR)

copyusr: createdirs
	$(call printInfo,Copying usr/ files to $(BUILD_DIR)/usr)
	$(EXEC_CP) -rL $(APPLICATION_DIR)/usr $(BUILD_DIR)

	$(call printInfo,Removing venture website templates)
	/bin/rm -rf $(BUILD_DIR)/usr/local/bin/website/*

copyfiles: copybase copyetc copyhome copyperf copyusr

configdocs: copyusr
	echo
	$(call printInfo,Installing documentation files to /usr/share/doc/server-configurator)
	$(EXEC_CP) $(APPLICATION_DIR)/doc/* $(BUILD_DIR)/usr/share/doc/server-configurator

	$(call printInfo,Compressing changelog / NEWS.txt / README.txt)
	/bin/gzip $(BUILD_DIR)/usr/share/doc/server-configurator/changelog
	/bin/gzip $(BUILD_DIR)/usr/share/doc/server-configurator/NEWS.txt
	/bin/gzip $(BUILD_DIR)/usr/share/doc/server-configurator/README.txt

installutils: copyusr
	echo
	$(call printInfo,Installing utilities to /usr/local)

	$(call printInfo,Creating symbolic links for /usr/local/bin/convert-number)
	/bin/ln -sT /usr/local/bin/convert-number $(BUILD_DIR)/usr/local/bin/binary
	/bin/ln -sT /usr/local/bin/convert-number $(BUILD_DIR)/usr/local/bin/decimal
	/bin/ln -sT /usr/local/bin/convert-number $(BUILD_DIR)/usr/local/bin/hex
	/bin/ln -sT /usr/local/bin/convert-number $(BUILD_DIR)/usr/local/bin/octal

	$(call printInfo,Creating symbolic links for /usr/local/bin/convert-temp)
	/bin/ln -sT /usr/local/bin/convert-temp $(BUILD_DIR)/usr/local/bin/celsius
	/bin/ln -sT /usr/local/bin/convert-temp $(BUILD_DIR)/usr/local/bin/fahrenheit
	/bin/ln -sT /usr/local/bin/convert-temp $(BUILD_DIR)/usr/local/bin/kelvin

	$(call printInfo,Creating symbolic links for $(INSTALL_DIR) files)
	/bin/ln -sT $(INSTALL_DIR)/configure-server.sh $(BUILD_DIR)/usr/local/sbin/configure-server

	$(call printInfo,Creating symbolic links for $(INSTALL_DIR)/etc files)
	/bin/ln -sT $(INSTALL_DIR)/etc/configure-fstab.sh $(BUILD_DIR)/usr/local/sbin/configure-fstab
	/bin/ln -sT $(INSTALL_DIR)/etc/configure-kernel.sh $(BUILD_DIR)/usr/local/sbin/configure-kernel
	/bin/ln -sT $(INSTALL_DIR)/etc/configure-sshguard.sh $(BUILD_DIR)/usr/local/sbin/configure-sshguard
	/bin/ln -sT $(INSTALL_DIR)/etc/configure-system.sh $(BUILD_DIR)/usr/local/sbin/configure-system
	/bin/ln -sT $(INSTALL_DIR)/etc/apt/configure-apt-mirror.sh $(BUILD_DIR)/usr/local/sbin/configure-apt-mirror
	/bin/ln -sT $(INSTALL_DIR)/etc/default/configure-grub.sh $(BUILD_DIR)/usr/local/sbin/configure-grub
	/bin/ln -sT $(INSTALL_DIR)/etc/logwatch/configure-logwatch.sh $(BUILD_DIR)/usr/local/sbin/configure-logwatch
	/bin/ln -sT $(INSTALL_DIR)/etc/netplan/configure-netplan.sh $(BUILD_DIR)/usr/local/sbin/configure-netplan
	/bin/ln -sT $(INSTALL_DIR)/etc/network/configure-firewall.sh $(BUILD_DIR)/usr/local/sbin/configure-firewall
	/bin/ln -sT $(INSTALL_DIR)/etc/network/firewall-restore.sh $(BUILD_DIR)/usr/local/sbin/firewall-restore
	/bin/ln -sT $(INSTALL_DIR)/etc/network/ip6tables-private.sh $(BUILD_DIR)/usr/local/sbin/ip6tables-private
	/bin/ln -sT $(INSTALL_DIR)/etc/network/ip6tables-public.sh $(BUILD_DIR)/usr/local/sbin/ip6tables-public
	/bin/ln -sT $(INSTALL_DIR)/etc/network/ipset-config.sh $(BUILD_DIR)/usr/local/sbin/ipset-config
	/bin/ln -sT $(INSTALL_DIR)/etc/network/iptables-private.sh $(BUILD_DIR)/usr/local/sbin/iptables-private
	/bin/ln -sT $(INSTALL_DIR)/etc/network/iptables-public.sh $(BUILD_DIR)/usr/local/sbin/iptables-public
	/bin/ln -sT $(INSTALL_DIR)/etc/networkd-dispatcher/configure-nic.sh $(BUILD_DIR)/usr/local/sbin/configure-nic
	/bin/ln -sT $(INSTALL_DIR)/etc/security/configure-security.sh $(BUILD_DIR)/usr/local/sbin/configure-security
	/bin/ln -sT $(INSTALL_DIR)/etc/udev/configure-udev.sh $(BUILD_DIR)/usr/local/sbin/configure-udev
	/bin/ln -sT $(INSTALL_DIR)/etc/unbound/configure-unbound.sh $(BUILD_DIR)/usr/local/sbin/configure-unbound

	$(call printInfo,Creating symbolic links for $(INSTALL_DIR)/home files)
	/bin/ln -sT $(INSTALL_DIR)/home/configure-user.sh $(BUILD_DIR)/usr/local/sbin/configure-user

	$(call printInfo,Creating symbolic links for $(INSTALL_DIR)/services files)
	/bin/ln -sT $(INSTALL_DIR)/services/install-ssl.sh $(BUILD_DIR)/usr/local/sbin/install-ssl
	/bin/ln -sT $(INSTALL_DIR)/services/install-httpd.sh $(BUILD_DIR)/usr/local/sbin/install-httpd

applysecurity: copyfiles configdocs installutils
	echo
	$(call printInfo,Applying security settings to $(INSTALL_DIR))
	/usr/bin/find $(BUILD_DIR)/$(INSTALL_DIR) -type f \( ! -name "*.sh" ! -name "*.tpl" \) -exec /bin/chmod 640 {} +
	/usr/bin/find $(BUILD_DIR)/$(INSTALL_DIR) -type f \( -name "*.sh" -o -name "*.tpl" \) -exec /bin/chmod 750 {} +

	$(call printInfo,Applying security settings to /etc)
	/usr/bin/find $(BUILD_DIR)/etc -type d -exec /bin/chmod 00755 {} +
	/bin/chmod 644 $(BUILD_DIR)/etc/devops/*
	/bin/chown -R root:root $(BUILD_DIR)/etc

	$(call printInfo,Applying security settings to /usr)
	/usr/bin/find $(BUILD_DIR)/usr -type d -exec /bin/chmod 00755 {} +
	/bin/chown -R root:root $(BUILD_DIR)/usr

	$(call printInfo,Applying security settings to /usr/share/doc/server-configurator)
	/bin/chmod 644 $(BUILD_DIR)/usr/share/doc/server-configurator/*

	$(call printInfo,Applying security settings to /usr/local/bin)
	/bin/chmod -R 755 $(BUILD_DIR)/usr/local/bin/*
	/bin/chown -R --no-dereference root:users $(BUILD_DIR)/usr/local/bin/*

	$(call printInfo,Applying security settings to /usr/local/sbin)
	/bin/chmod 750 $(BUILD_DIR)/usr/local/sbin/*
	/bin/chown --no-dereference root:sudo $(BUILD_DIR)/usr/local/sbin/*

package: applysecurity
	echo
	$(call printInfo,Installing $(BUILD_DIR)/DEBIAN/control file)
	$(EXEC_CP) $(CURDIR)/DEBIAN/control $(BUILD_DIR)/DEBIAN

	/usr/local/bin/deb-control $(BUILD_DIR)

	$(call printInfo,Installing $(BUILD_DIR)/DEBIAN/conffiles file)
	$(EXEC_CP) $(CURDIR)/DEBIAN/conffiles $(BUILD_DIR)/DEBIAN

	$(call printInfo,Installing $(BUILD_DIR)/DEBIAN/preinst file)
	$(EXEC_CP) $(CURDIR)/DEBIAN/preinst $(BUILD_DIR)/DEBIAN

	$(call printInfo,Generating DEBIAN/md5sums file)
	/usr/local/bin/md5sums $(BUILD_DIR)

	$(call printInfo,Applying security settings to /DEBIAN files)
	/bin/chmod 644 $(BUILD_DIR)/DEBIAN/control $(BUILD_DIR)/DEBIAN/conffiles $(BUILD_DIR)/DEBIAN/md5sums
	/bin/chmod 755 $(BUILD_DIR)/DEBIAN/preinst

	echo
	$(call printInfo,Building $(PKG_ARCHIVE).deb)
	/usr/bin/dpkg-deb -b $(BUILD_DIR)
	/bin/mv $(TMPDIR)/$(PKG_ARCHIVE).deb $(RELEASE_DIR)

	echo
	$(call printInfo,Generating SHA256SUM and fileinfo.html)
	cd $(RELEASE_DIR) && \
	/usr/bin/sha256sum $(PKG_ARCHIVE).deb > SHA256SUM && \
	/usr/local/bin/venture fileinfo $(PKG_ARCHIVE).deb

	/bin/chown -R $${SUDO_USER}:$${SUDO_USER} $(RELEASE_DIR)
	/bin/chmod 640 $(RELEASE_DIR)/*

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
	echo "    INSTALL_DIR: $(INSTALL_DIR)"
	echo
