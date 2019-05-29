#!/bin/bash

#
# configure-grub.sh - DevOpsBroker script for configuring GRUB boot loader
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
# See https://www.gnu.org/software/grub/manual/grub/grub.html for more
# information on GRUB.
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

# Ensure the grub.tpl script is executable
grubTpl=$(isExecutable "$SCRIPT_DIR"/grub.tpl)

################################## Variables ##################################

## Bash exec variables
EXEC_ARCH=/usr/bin/arch
EXEC_UPDATE_GRUB=/usr/sbin/update-grub
EXEC_UPDATE_INITRAMFS=/usr/sbin/update-initramfs

## Variables
export TMPDIR=${TMPDIR:-'/tmp'}
echoOnExit=false

# Amount of RAM available in GB
RAM_GB=$[ ($(getRamTotal) + 1048575) / 1048576 ]

# Configure ZSwap Max Pool Percentage
if [ $RAM_GB -le 8 ]; then
	zswapMaxPoolPct=20
elif [ $RAM_GB -le 16 ]; then
	zswapMaxPoolPct=15
else
	zswapMaxPoolPct=10
fi

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE GRUB Configurator" 'true'

#
# Fix Ubuntu installer bug with it not installing grub-efi-amd64 package
#

if [ -d /sys/firmware/efi ] && [ "$($EXEC_ARCH)" == 'x86_64' ] && [ ! -L /usr/share/doc/grub-efi-amd64 ]; then
	printBanner "Installing grub-efi-amd64"
	$EXEC_APT -y install grub-efi-amd64
	echo
fi

#
# GRUB Configuration
#

if ! $EXEC_GREP -Fq 'DevOpsBroker' /etc/default/grub; then

	printBanner 'Installing GRUB configuration'

	# Execute template script
	"$grubTpl" $zswapMaxPoolPct > "$TMPDIR"/grub

	# Install as root:root with rw-r--r-- privileges
	$EXEC_INSTALL -b --suffix .orig -o root -g root -m 644 "$TMPDIR"/grub /etc/default

	# Clean up
	$EXEC_RM "$TMPDIR"/grub

	printInfo 'Generate a new GRUB configuration file'
	$EXEC_UPDATE_GRUB

	if ! $EXEC_GREP -Fq '# Enable lz4 Compression for zswap' /etc/initramfs-tools/modules; then
		# Backup original /etc/initramfs-tools/modules file
		$EXEC_CP /etc/initramfs-tools/modules /etc/initramfs-tools/modules.orig

		printInfo 'Enable lz4 compression z3fold pool for zswap'
		echo -e "\n# Enable lz4 Compression for zswap\nlz4\nlz4_compress" >> /etc/initramfs-tools/modules
		echo -e "\n# Enable z3fold Pool for zswap\nz3fold" >> /etc/initramfs-tools/modules

		printInfo 'Generate a new initramfs image'
		$EXEC_UPDATE_INITRAMFS -u
	fi

	echoOnExit=true

else
	currentMaxPoolPct=$($EXEC_CAT /sys/module/zswap/parameters/max_pool_percent)

	if [ $currentMaxPoolPct -ne $zswapMaxPoolPct ] || [ "$grubTpl" -nt /etc/default/grub ]; then
		printBanner 'Updating GRUB configuration'

		# Execute template script
		"$grubTpl" $zswapMaxPoolPct > "$TMPDIR"/grub

		# Install as root:root with rw-r--r-- privileges
		$EXEC_INSTALL -b --suffix .bak -o root -g root -m 644 "$TMPDIR"/grub /etc/default

		# Clean up
		$EXEC_RM "$TMPDIR"/grub

		printInfo 'Generate a new GRUB configuration file'
		$EXEC_UPDATE_GRUB
		echoOnExit=true
	fi
fi

if [ "$echoOnExit" == 'true' ]; then
	echo
fi

exit 0
