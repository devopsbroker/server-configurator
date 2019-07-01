#!/bin/bash

#
# configure-udev.sh - DevOpsBroker script for configuring udev rules
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
# Measure read speed of any drive (Hard Drive/SSD/USB):
#   o hdparm -t /dev/sd(a|b|c|d...)
#
# Call block device ioctls:
#   o sudo blockdev --report /dev/sda
#
# View all attached storage devices and their partitions:
#   o sudo fdisk -l
#
# View block device attributes:
#   o sudo blkid -o udev -p /dev/sdc1
#
# Probe USB hardward information:
#   o hwinfo --usb
#
# View verbose USB device information:
#   o sudo lsusb -v -d 0x090c:0x1000
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

# Load /etc/devops/functions-admin.conf if FUNC_ADMIN_CONFIG is unset
if [ -z "$FUNC_ADMIN_CONFIG" ] && [ -f /etc/devops/functions-admin.conf ]; then
	source /etc/devops/functions-admin.conf
fi

${FUNC_ADMIN_CONFIG?"[1;91mCannot load '/etc/devops/functions-admin.conf': No such file[0m"}

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

# Ensure the tune-diskio.tpl script is executable
tuneDiskIOTpl=$(isExecutable "$SCRIPT_DIR"/rules.d/tune-diskio.tpl)

################################## Variables ##################################

## Bash exec variables
EXEC_LSBLK=/bin/lsblk

## Variables
IS_VM_GUEST=0
export TMPDIR=${TMPDIR:-'/tmp'}
echoOnExit=false

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE Udev Configurator" 'true'

# Detect whether Ubuntu Server is running as a guest in a virtual machine
detectVirtualization

if [ $IS_VM_GUEST -ne 0 ]; then
	printNotice $SCRIPT_EXEC 'Server is running as a virtual machine...exiting'
	echo
	exit 0
fi

#
# Disk I/O Schedulers Configuration
#   o /etc/udev/rules.d/60-io-schedulers.rules
#   o Queue scheduler: kyber
#

installConfig '60-io-schedulers.rules' "$SCRIPT_DIR"/rules.d /etc/udev/rules.d

#
# Disk I/O Tuning Configuration
#   o /etc/udev/rules.d/tune-diskio.tpl
#

# List all currently mounted block devices

mapfile -t blockDeviceList < <($EXEC_LSBLK -dnp --exclude 7 --output NAME,SERIAL)

for blockDevice in "${blockDeviceList[@]}"; do
	IFS=' '; attributeList=( $blockDevice ); IFS=$'\n\t'

	if [ ${#attributeList[@]} -eq 2 ]; then
		if [ ! -f "/etc/udev/rules.d/65-diskio-${attributeList[1]}.rules" ] || \
			[ "$tuneDiskIOTpl" -nt "/etc/udev/rules.d/65-diskio-${attributeList[1]}.rules" ]; then
			printInfo "Tuning Disk I/O for block device '${attributeList[0]}'"

			# Execute template script
			$tuneDiskIOTpl ${attributeList[0]}

			echoOnExit=true
		fi
	fi
done

if [ "$echoOnExit" == 'true' ]; then
	echo
fi

exit 0
