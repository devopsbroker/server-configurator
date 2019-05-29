#!/bin/bash

#
# configure-sshguard.sh - DevOpsBroker administration script for configuring sshguard
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
# Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-16
#
# The following systemwide initialization files are configured by this script:
#
# o /etc/apt/preferences.d/disco.pref
# o /etc/sshguard/sshguard.conf
# o /etc/systemd/system/sshguard.service
# -----------------------------------------------------------------------------
#

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Preprocessing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

# Load /etc/devops/functions-admin.conf if FUNC_ADMIN_CONFIG is unset
if [ -z "$FUNC_ADMIN_CONFIG" ] && [ -f /etc/devops/functions-admin.conf ]; then
	source /etc/devops/functions-admin.conf
fi

${FUNC_ADMIN_CONFIG?"[1;91mCannot load '/etc/devops/functions-admin.conf': No such file[0m"}

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

## Variables
installDisco=false

################################### Actions ###################################

# Install /etc/apt/preferences.d/disco.pref
if [ ! -f /etc/apt/preferences.d/disco.pref ]; then
	printInfo 'Installing /etc/apt/preferences.d/disco.pref'

	# Install as root:root with rw-r--r-- privileges
	/usr/bin/install -o root -g root -m 644 "$SCRIPT_DIR/etc/apt/preferences.d/disco.pref" /etc/apt/preferences.d

	installDisco=true
fi

# Install /etc/apt/sources.list.d/disco.list
if [ ! -f /etc/apt/sources.list.d/disco.list ]; then
	printInfo 'Installing /etc/apt/sources.list.d/disco.list'

	# Install as root:root with rw-r--r-- privileges
	/usr/bin/install -o root -g root -m 644 "$SCRIPT_DIR/etc/apt/sources.list.d/disco.list" /etc/apt/sources.list.d

	installDisco=true
fi

# Install disco version of sshguard
if [ "$installDisco" == 'true' ]; then
	printBanner 'Installing sshguard'
	$EXEC_APT update
	$EXEC_APT -y install --no-install-recommends sshguard
fi

# Install /etc/sshguard/sshguard.conf
installConfig 'sshguard.conf' "$SCRIPT_DIR/sshguard" /etc/sshguard

if [ "$INSTALL_CONFIG" == 'true' ]; then
	printInfo 'Restarting sshguard service'
	$EXEC_SYSTEMCTL restart sshguard.service
fi

# Install /etc/systemd/system/sshguard.service
installConfig 'sshguard.service' "$SCRIPT_DIR"/systemd/system /etc/systemd/system

if [ "$INSTALL_CONFIG" == 'true' ]; then
	$EXEC_SYSTEMCTL daemon-reload

	printInfo 'Enabling sshguard.service'
	$EXEC_SYSTEMCTL enable sshguard.service

	printInfo 'Starting sshguard.service'
	$EXEC_SYSTEMCTL start sshguard.service
fi

exit 0
