#!/bin/bash

#
# configure-unbound.sh - DevOpsBroker script for configuring unbound DNS cache server
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
# Developed on Ubuntu 18.04.1 LTS running kernel.osrelease = 4.15.0-45
#
# Useful Linux Command-Line Utilities
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Use DNS lookup utility to see unbound in action (run twice):
#   o dig ubuntu.com
#
# Query Internet name servers interactively:
#   o nslookup google.com
# -----------------------------------------------------------------------------
#

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Preprocessing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Load /etc/devops/ansi.conf if ANSI_CONFIG is unset
if [ -z "$ANSI_CONFIG" ] && [ -f /etc/devops/ansi.conf ]; then
	source /etc/devops/ansi.conf
fi

${ANSI_CONFIG?"[1;91mCannot load '/etc/devops/ansi.conf': No such file[0m"}

# Load /etc/devops/exec.conf if EXEC_CONFIG is unset
if [ -z "$EXEC_CONFIG" ] && [ -f /etc/devops/exec.conf ]; then
	source /etc/devops/exec.conf
fi

${EXEC_CONFIG?"[1;91mCannot load '/etc/devops/exec.conf': No such file[0m"}

# Load /etc/devops/functions.conf if FUNC_CONFIG is unset
if [ -z "$FUNC_CONFIG" ] && [ -f /etc/devops/functions.conf ]; then
	source /etc/devops/functions.conf
fi

${FUNC_CONFIG?"[1;91mCannot load '/etc/devops/functions.conf': No such file[0m"}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Robustness ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

set -o errexit                 # Exit if any statement returns a non-true value
set -o nounset                 # Exit if use an uninitialised variable
set -o pipefail                # Exit if any statement in a pipeline returns a non-true value
IFS=$'\n\t'                    # Default the Internal Field Separator to newline and tab

## Script information
SCRIPT_INFO=( $($EXEC_SCRIPTINFO "$BASH_SOURCE") )
SCRIPT_DIR="${SCRIPT_INFO[0]}"
SCRIPT_EXEC="${SCRIPT_INFO[1]}"

# Display error if not running as root
if [ "$USER" != 'root' ]; then
	printError $SCRIPT_EXEC 'Permission denied (you must be root)'
	exit 1
fi

################################## Variables ##################################

## Bash exec variables
EXEC_TOUCH=/usr/bin/touch

## Variables
echoOnExit=false
restartUnbound=false

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE Unbound Configurator" 'true'

#
# unbound User Configuration
#
if ! $EXEC_GROUPS unbound | $EXEC_GREP -Fq 'syslog'; then
	printInfo 'Adding unbound user to the syslog group'
	$EXEC_ADDUSER unbound syslog

	echoOnExit=true
fi

#
# /var/log/unbound.log File
#
if [ ! -f /var/log/unbound.log ]; then
	printInfo 'Creating /var/log/unbound.log'
	$EXEC_TOUCH /var/log/unbound.log
	$EXEC_CHOWN --changes unbound:unbound /var/log/unbound.log

	echoOnExit=true
fi

#
# /etc/unbound/unbound.conf.d/ Configuration
#
if [ ! -f /etc/unbound/unbound.conf.d/dns-cache-server.conf ]; then
	printInfo 'Configuring unbound DNS cache server'

	# Delete any default configurations in /etc/unbound/unbound.conf.d
	$EXEC_RM /etc/unbound/unbound.conf.d/*

	# Install as root:root with rw-r--r-- privileges
	$EXEC_INSTALL -o root -g root -m 644 "$SCRIPT_DIR"/unbound.conf.d/dns-cache-server.conf /etc/unbound/unbound.conf.d

	echoOnExit=true
	restartUnbound=true

elif [ "$SCRIPT_DIR"/unbound.conf.d/dns-cache-server.conf -nt /etc/unbound/unbound.conf.d/dns-cache-server.conf ]; then
	printInfo 'Updating unbound DNS cache server configuration'

	# Install as root:root with rw-r--r-- privileges
	$EXEC_INSTALL -b --suffix .bak -o root -g root -m 644 "$SCRIPT_DIR"/unbound.conf.d/dns-cache-server.conf /etc/unbound/unbound.conf.d

	echoOnExit=true
	restartUnbound=true
fi

#
# Disable systemd-resolved.service
#
set +o errexit
if [ "$($EXEC_SYSTEMCTL status systemd-resolved.service | $EXEC_GREP -F 'active (running)')" ]; then
	printInfo 'Stopping systemd-resolved.service'
	$EXEC_SYSTEMCTL stop systemd-resolved.service

	printInfo 'Disabling systemd-resolved.service'
	$EXEC_SYSTEMCTL disable systemd-resolved.service

	echoOnExit=true
fi

#
# Enable unbound.service
#
if [ -z "$($EXEC_SYSTEMCTL status unbound.service | $EXEC_GREP -F 'active (running)')" ]; then
	printInfo 'Enabling unbound.service'
	$EXEC_SYSTEMCTL enable unbound.service

	printInfo 'Starting unbound.service'
	$EXEC_SYSTEMCTL start unbound.service

	echoOnExit=true
	restartUnbound=false
fi

#
# Enable unbound-resolvconf.service
#
if [ -z "$($EXEC_SYSTEMCTL status unbound-resolvconf.service | $EXEC_GREP -F 'active (running)')" ]; then
	printInfo 'Enabling unbound-resolvconf.service'
	$EXEC_SYSTEMCTL enable unbound-resolvconf.service

	printInfo 'Starting unbound-resolvconf.service'
	$EXEC_SYSTEMCTL start unbound-resolvconf.service

	echoOnExit=true
fi
set -o errexit

if [ "$restartUnbound" == 'true' ]; then
	printInfo 'Restarting unbound.service'
	$EXEC_SYSTEMCTL restart unbound.service
fi

if [ "$echoOnExit" == 'true' ]; then
	echo
fi

exit 0
