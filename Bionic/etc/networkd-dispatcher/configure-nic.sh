#!/bin/bash

#
# configure-nic.sh - DevOpsBroker script for configuring network interfaces
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
# Display network interface configuration including txqueuelength:
#   o ip link show dev enp31s0
#
# Display current Ethernet device settings:
#   o ethtool enp31s0
#
# Display Ethernet device features:
#   o ethtool -k enp31s0
#
# Display Ethernet device rx/tx ring parameter information:
#   o ethtool -g enp31s0
#
# Display Ethernet device interrupt coalescing information:
#   o ethtool -c enp31s0
#
# Display Ethernet device statistics:
#   o ethtool -S enp31s0
#
# Bounce the network interface:
#   o sudo ifdown enp31s0 && sudo ifup enp31s0
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
EXEC_NETTUNER=/usr/local/bin/nettuner

## Options
NIC="${1:-$($EXEC_IP -4 route show default | $EXEC_SORT -k9 -n | $EXEC_HEAD -1 | $EXEC_AWK '{print $5}')}"

## Variables
export TMPDIR=${TMPDIR:-'/tmp'}
echoOnExit=false

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE Network Interface Configurator" 'true'

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Display error if network interface parameter is invalid
if [ ! -L /sys/class/net/$NIC ]; then
	printError "$SCRIPT_EXEC" "Cannot access '$NIC': No such network interface"
	echo
	printUsage "$SCRIPT_EXEC NIC"

	exit 1
fi

# Exit if default interface is a virtual network device (i.e. bridge, tap, etc)
if [[ "$($EXEC_READLINK /sys/class/net/$NIC)" == *"/devices/virtual/"* ]]; then
	printInfo "Default network interface '$NIC' is virtual"
	printInfo 'Exiting'

	exit 0
fi

# ---------------------------- Network Information ----------------------------

# Internet Download speed
INET_DL_SPEED=$($EXEC_AWK '/Download:/{ print $2 }' /etc/devops/speedtest.info)

# Internet Upload speed
INET_UL_SPEED=$($EXEC_AWK '/Upload:/{ print $2 }' /etc/devops/speedtest.info)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Tasks ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#
# Create /etc/networkd-dispatcher/routable.d directory
#
if [ ! -d /etc/networkd-dispatcher/routable.d ]; then
	printInfo 'Creating /etc/networkd-dispatcher/routable.d directory'
	$EXEC_MKDIR --parents /etc/networkd-dispatcher/routable.d
fi

#
# /etc/networkd-dispatcher/routable.d Configuration
#

if [ ! -f /etc/networkd-dispatcher/routable.d/tune-$NIC ]; then
	printInfo "Installing /etc/networkd-dispatcher/routable.d/tune-$NIC"

	# Execute nettuner
	$($EXEC_NETTUNER -d $INET_DL_SPEED -u $INET_UL_SPEED -g networkd $NIC > "$TMPDIR"/tune-$NIC)

	# Install as root:root with rwxr-xr-x privileges
	$EXEC_INSTALL -o root -g root -m 755 "$TMPDIR"/tune-$NIC /etc/networkd-dispatcher/routable.d

	# Clean up
	$EXEC_RM "$TMPDIR"/tune-$NIC

	echoOnExit=true

elif [ "$EXEC_NETTUNER" -nt /etc/networkd-dispatcher/routable.d/tune-$NIC ]; then
	printInfo "Updating /etc/networkd-dispatcher/routable.d/tune-$NIC"

	# Execute nettuner
	$($EXEC_NETTUNER -d $INET_DL_SPEED -u $INET_UL_SPEED -g networkd $NIC > "$TMPDIR"/tune-$NIC)

	# Install as root:root with rwxr-xr-x privileges
	$EXEC_INSTALL -o root -g root -m 755 "$TMPDIR"/tune-$NIC /etc/networkd-dispatcher/routable.d

	# Clean up
	$EXEC_RM "$TMPDIR"/tune-$NIC

	echoOnExit=true
fi

if [ $echoOnExit == 'true' ]; then
	echo
fi

exit 0
