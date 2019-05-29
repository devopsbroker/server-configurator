#!/bin/bash

#
# grub.tpl - DevOpsBroker script for generating /etc/default/grub configuration
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
# GRUB Kernel configurations include:
#   o Enable zswap (lz4 compressor / z3fold zpool)
#   o Enable 'tickless' scheduling-clock interrupts
#   o Enable Multi-Queue Block I/O Queueing
#   o Enable Virtual Dynamic Shared Object (VDSO) support
#   o Offload all RCU Callbacks to the kernel
#   o Disable NMI Watchdog
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

scriptName='grub.tpl'

# Display error if not running as root
if [ "$USER" != 'root' ]; then
	printError $scriptName 'Permission denied (you must be root)'
	exit 1
fi

################################## Variables ##################################

## Configuration
ONLINE_CPUS=$($EXEC_CAT /sys/devices/system/cpu/online)

## Options
zswapMaxPoolPct=${1:-}

## Variables
YEAR=$($EXEC_DATE +'%Y')
IS_VM_GUEST=0

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Display usage if no parameters given
if [ -z "$zswapMaxPoolPct" ]; then
	printUsage "$scriptName ZSWAP_MAX_POOL_PCT"
	exit 1
fi

# Display error if invalid zswap max pool percent specified
if [[ ! "$zswapMaxPoolPct" =~ ^[0-9]+$ ]] || \
		[ "$zswapMaxPoolPct" -lt 0 ] || \
		[ "$zswapMaxPoolPct" -gt 100 ]; then
	printError $scriptName "Invalid ZSwap max pool percentage $zswapMaxPoolPct"
	echo
	printUsage "$scriptName ZSWAP_MAX_POOL_PCT"

	exit 1
fi

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Detect whether Ubuntu Server is running as a guest in a virtual machine
detectVirtualization

## Template variables
isEfiBoot=$([ -d /sys/firmware/efi ] && echo -n 'true' || echo -n 'false')
efiReboot=$([ "$isEfiBoot" == 'true' ] && echo -n 'reboot=efi' || echo -n '')

defaultCmdLine="zswap.enabled=1 zswap.compressor=lz4 zswap.zpool=z3fold zswap.max_pool_percent=$zswapMaxPoolPct"
defaultCmdLine="$defaultCmdLine nmi_watchdog=0 nohz=on rcu_nocbs=$ONLINE_CPUS"
defaultCmdLine="$defaultCmdLine rcu_nocb_poll vdso=1"

if [ $IS_VM_GUEST -eq 0 ]; then
	defaultCmdLine="$defaultCmdLine scsi_mod.use_blk_mq=1"
else
	defaultCmdLine="$defaultCmdLine elevator=noop"
fi

if [ "$isEfiBoot" = 'true' ]; then
	defaultCmdLine="acpi=force $defaultCmdLine"
fi

## Template
/bin/cat << EOF
#
# grub - DevOpsBroker configuration for /etc/default/grub
#
# Copyright (C) $YEAR Edward Smith <edwardsmith@devopsbroker.org>
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
# If you change this file, run 'update-grub' afterwards to update
# /boot/grub/grub.cfg.
#
# For full documentation of the options in this file, see:
#   info -f grub -n 'Simple configuration'
#
# - See https://help.ubuntu.com/community/UEFI about booting using UEFI.
# - See https://wiki.archlinux.org/index.php/GRUB/Tips_and_tricks for GRUB tips
#   and tricks.
# -----------------------------------------------------------------------------
#

GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=countdown
GRUB_TIMEOUT=0
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="$defaultCmdLine"
GRUB_CMDLINE_LINUX="$efiReboot"

# Uncomment to enable BadRAM filtering, modify to suit your needs
# This works with Linux (no patch required) and with any kernel that obtains
# the memory map information from GRUB (GNU Mach, kernel of FreeBSD ...)
#GRUB_BADRAM="0x01234567,0xfefefefe,0x89abcdef,0xefefefef"

# Uncomment to disable graphical terminal (grub-pc only)
#GRUB_TERMINAL=console

# The resolution used on graphical terminal
# note that you can use only modes which your graphic card supports via VBE
# you can see them in real GRUB with the command 'vbeinfo'
#GRUB_GFXMODE=1280x960x16
#GRUB_GFXPAYLOAD_LINUX=keep

# Uncomment if you don't want GRUB to pass "root=UUID=xxx" parameter to Linux
#GRUB_DISABLE_LINUX_UUID=true

# Uncomment to disable generation of recovery mode menu entries
#GRUB_DISABLE_RECOVERY="true"

# Uncomment to get a beep at grub start
#GRUB_INIT_TUNE="480 440 1"

EOF

exit 0
