#!/bin/bash

#
# configure-firewall.sh - DevOpsBroker script for iptables/ip6tables configurations
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

################################## Functions ##################################

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     installPackage
# Description:  Installs the specified package, if not already installed
#
# Parameter $1: The file to check for existence; install if not present
# Parameter $2: The name of the package to install
# -----------------------------------------------------------------------------
function installPackage() {
	INSTALL_PKG='false'

	if [ ! -f "$1" ]; then
		printBanner "Installing $2"
		$EXEC_APT -y install $2
		echo

		INSTALL_PKG='true'
	fi
}

################################## Variables ##################################

## Bash exec variables
IPTABLES_RESTORE=/sbin/iptables-restore
IP6TABLES_RESTORE=/sbin/ip6tables-restore
IPSET=/sbin/ipset

## Options
DEFAULT_NIC="${1:-}"

## Variables
IPSET_UPDATE='false'

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Find the default NIC if one was not provided as an option
if [ -z "$DEFAULT_NIC" ]; then
	set +o errexit
	mapfile -t ethList < <($EXEC_IP -br -4 addr show | $EXEC_GREP -Eo '^e[a-z0-9]+')
	set -o errexit

	if [ ${#ethList[@]} -eq 1 ]; then
		DEFAULT_NIC=(${ethList[0]})
	else
		COLUMNS=1
		echo "${bold}${yellow}Which Ethernet interface do you want to configure?${white}"
		select DEFAULT_NIC in ${ethList[@]}; do
			for nic in ${ethList[@]}; do
				if [ "$nic" == "$DEFAULT_NIC" ]; then
					break;
				fi
			done
		done
	fi
fi

################################### Actions ###################################

echo "${bold}${yellow}Where is this Ubuntu Server deployed?${white}"
select DEPLOY_ENV in 'Public Internet' 'Private Intranet'; do
	if [[ "$DEPLOY_ENV" =~ ^Public ]]; then

		IPTABLES_SCRIPT="$SCRIPT_DIR/iptables-public.sh"
		IP6TABLES_SCRIPT="$SCRIPT_DIR/ip6tables-public.sh"

		break;
	elif [[ "$DEPLOY_ENV" =~ ^Private ]]; then
		IPTABLES_SCRIPT="$SCRIPT_DIR/iptables-private.sh"
		IP6TABLES_SCRIPT="$SCRIPT_DIR/ip6tables-private.sh"

		break;
	fi
done

# Install ipset
installPackage '/sbin/ipset' 'ipset'

# Install iptables
installPackage '/sbin/iptables' 'iptables'

# Call ipset-config.sh
if [ ! -f /etc/network/ipset.conf ] || \
	[ "$SCRIPT_DIR/ipset-config.sh" -nt /etc/network/ipset.conf ]; then

		"$SCRIPT_DIR/ipset-config.sh"
		IPSET_UPDATE='true'
		echo
else
	# Check to see if IPSet has already been loaded
	set +o errexit

	$IPSET test tcp_service_ports 22

	if [ $? -ne 0 ]; then
		printInfo 'Loading /etc/network/ipset.conf configuration'
		/usr/bin/logger -p syslog.notice -i [ipset-restore] Loading /etc/network/ipset.conf configuration;
		$IPSET restore -file /etc/network/ipset.conf
	fi

	set -o errexit
	echo
fi

# Configure IPv4 firewall
if [ ! -f /etc/network/iptables.rules ] || \
	[ "$IPTABLES_SCRIPT" -nt /etc/network/iptables.rules ] || \
	[ "$IPSET_UPDATE" == 'true' ]; then

		"$IPTABLES_SCRIPT" $DEFAULT_NIC
		echo
else
	printInfo 'Loading /etc/network/iptables.rules'
	/usr/bin/logger -p syslog.notice -i [iptables-restore] Loading /etc/network/iptables.rules;
	$IPTABLES_RESTORE < /etc/network/iptables.rules
fi

# Configure IPv6 firewall
if [ ! -f /etc/network/ip6tables.rules ] || \
	[ "$IP6TABLES_SCRIPT" -nt /etc/network/ip6tables.rules ] || \
	[ "$IPSET_UPDATE" == 'true' ]; then

		"$IP6TABLES_SCRIPT" $DEFAULT_NIC
		echo
else
	printInfo 'Loading /etc/network/ip6tables.rules'
	/usr/bin/logger -p syslog.notice -i [ip6tables-restore] Loading /etc/network/ip6tables.rules;
	$IP6TABLES_RESTORE < /etc/network/ip6tables.rules
fi

exit 0
