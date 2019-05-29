#!/bin/bash

#
# configure-kernel.sh - DevOpsBroker script for configuring Linux kernel tuning
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
# Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-15
#
# See sysctl(8) and sysctl.conf(5) for more information.
#
# Useful Linux Command-Line Utilities
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Show the complete list of all sysctl parameters:
#   o sysctl -a
#
# Set the MTU on a network interface:
#   o ifconfig enp4s0 mtu NNNN
#
# Monitor kernel behavior with regard to the VM dirty pages:
#   o grep -A 1 dirty /proc/vmstat
#
# Check cwnd runtime value:
#   o ss -nli | fgrep cwnd
#
# Determine Connection States:
#   o netstat -tan | grep ':80 ' | awk '{print $6}' | sort | uniq -c
#
# View TCP/UDP/IP Session Information:
#   o ss -s
#
# TODO: Audit kernel parameters to ensure they are properly set
# TODO: Audit security settings (i.e. umask) to ensure they are properly set,
#       especially for someone in the sudo group
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

# Load /etc/devops/functions-io.conf if FUNC_IO_CONFIG is unset
if [ -z "$FUNC_IO_CONFIG" ] && [ -f /etc/devops/functions-io.conf ]; then
	source /etc/devops/functions-io.conf
fi

${FUNC_IO_CONFIG?"[1;91mCannot load '/etc/devops/functions-io.conf': No such file[0m"}

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

# Ensure the sysctl.conf.tpl script is executable
sysctlConf=$(isExecutable "$SCRIPT_DIR"/sysctl.conf.tpl)

################################## Functions ##################################

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     execSpeedTest
# Description:  Executes the Internet Speed Test
# -----------------------------------------------------------------------------
function execSpeedTest() {
	# Install speedtest-cli if necessary
	if [ ! -f $EXEC_SPEED_TEST ]; then
		printBanner 'Installing speedtest-cli'
		$EXEC_APT -y install speedtest-cli
		echo
	fi

	if [ ! -f /etc/devops/speedtest.info ]; then
		printInfo 'Executing Internet speed test'
		$EXEC_SPEED_TEST | tee /etc/devops/speedtest.info

		printInfo 'Internet speed test finished'
		echo
	fi
}

################################## Variables ##################################

## Bash exec variables
EXEC_SPEED_TEST=/usr/bin/speedtest-cli
EXEC_SYSCTL=/sbin/sysctl

## Variables
export TMPDIR=${TMPDIR:-'/tmp'}
echoOnExit=false

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Delete /etc/devops/speedtest.info on force kernel retune
if [ "${1:-}" == '-f' ]; then
	$EXEC_RM -f /etc/devops/speedtest.info 2>/dev/null
fi

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE Kernel Tuning Configurator" 'true'

#
# Linux Kernel Tuning
#
if ! $EXEC_GREP -Fq 'DevOpsBroker' /etc/sysctl.conf; then

	printBanner 'Installing /etc/sysctl.conf'

	# Execute Internet speed test
	execSpeedTest

	# Execute template script
	"$sysctlConf" > "$TMPDIR"/sysctl.conf

	if [ -f "$TMPDIR/sysctl.conf" ] && [ -s "$TMPDIR/sysctl.conf" ]; then
		# Install as root:root with rw-r--r-- privileges
		$EXEC_INSTALL -b --suffix .orig -o root -g root -m 644 "$TMPDIR"/sysctl.conf /etc

		printInfo 'Load kernel tuning parameters from /etc/sysctl.conf'
		echo
		$EXEC_SYSCTL -p

		echoOnExit=true
	fi

	# Clean up
	$EXEC_RM "$TMPDIR"/sysctl.conf

elif [ "$sysctlConf" -nt /etc/sysctl.conf ] || [ "${1:-}" == '-f' ]; then

	printBanner 'Updating /etc/sysctl.conf'

	# Execute Internet speed test
	execSpeedTest

	# Execute template script
	"$sysctlConf" > "$TMPDIR"/sysctl.conf

	if [ -f "$TMPDIR/sysctl.conf" ] && [ -s "$TMPDIR/sysctl.conf" ]; then
		# Install as root:root with rw-r--r-- privileges
		$EXEC_INSTALL -b --suffix .bak -o root -g root -m 644 "$TMPDIR"/sysctl.conf /etc

		printInfo 'Load kernel tuning parameters from /etc/sysctl.conf'
		echo
		$EXEC_SYSCTL -p

		echoOnExit=true
	fi

	# Clean up
	$EXEC_RM "$TMPDIR"/sysctl.conf
fi

if [ "$echoOnExit" == 'true' ]; then
	echo
else
	printInfo '/etc/sysctl.conf already configured'
	echo
	printUsage "$SCRIPT_EXEC ${gold}[-f]"

	echo ${bold}
	echo "Valid Options:${romantic}"
	echo -e ${gold}'  -f\t'  ${romantic}'Force /etc/sysctl.conf reconfiguration'
	echo ${reset}
fi

exit 0
