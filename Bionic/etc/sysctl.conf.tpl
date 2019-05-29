#!/bin/bash

#
# sysctl.conf.tpl - DevOpsBroker script for generating /etc/sysctl.conf configuration
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
# Configuration file for setting system variables. See the /etc/sysctl.d/
# directory for additional system variable configuration files.
#
# See sysctl.conf(5) and sysctl(8) for more information.
#
# Protects from the following attacks:
#   o SYN Flood Attack
#   o TCP Time-Wait Attack
#   o Source IP Address Spoofing
#   o MITM Attacks
#   o Bad Error Messages
#
# Every kernel parameter that can be tuned specifically for your machine is
# dynamically calculated based upon your machine configuration, network
# interface, and Internet connection speed.
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

scriptName='sysctl.conf.tpl'

# Display error if not running as root
if [ "$USER" != 'root' ]; then
	printError $scriptName 'Permission denied (you must be root)'
	exit 1
fi

################################## Variables ##################################

## Bash exec variables
EXEC_NETTUNER=/usr/local/bin/nettuner
EXEC_SCHEDTUNER=/usr/local/sbin/schedtuner

## Options
NIC="${1:-$($EXEC_IP -4 route show default | $EXEC_SORT -k9 -n | $EXEC_HEAD -1 | $EXEC_AWK '{print $5}')}"

## Variables
export TMPDIR=${TMPDIR:-'/tmp'}
YEAR=$($EXEC_DATE +'%Y')
IS_VM_GUEST=0
SCHED_TUNING=''

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Display error if network interface parameter is invalid
if [ ! -L /sys/class/net/$NIC ]; then
	printError 'sysctl.conf.tpl' "Cannot access '$NIC': No such network interface"
	echo
	printUsage 'sysctl.conf.tpl NIC'

	exit 1
fi

# Exit if network interface is a virtual network device (i.e. bridge, tap, etc)
if [[ "$($EXEC_READLINK /sys/class/net/$NIC)" == *"/devices/virtual/"* ]]; then
	printInfo "Network interface '$NIC' is virtual"
	printInfo 'Exiting'

	exit 0
fi

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ General Information ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Total amount of RAM available
RAM_TOTAL=$(getRamTotal)

# Amount of RAM available in GB
RAM_GB=$[ ($RAM_TOTAL + 1048575) / 1048576 ]

# Detect whether Ubuntu Server is running as a guest in a virtual machine
detectVirtualization

if [ $IS_VM_GUEST -eq 0 ]; then

	SCHED_TUNING="$($EXEC_SCHEDTUNER)"

else
	CPU_MAX_FREQ=''
	MEM_BUS_SPEED=''

	while [ -z "$CPU_MAX_FREQ" ]; do
		read -p 'What is the CPU maximum frequency?: ' CPU_MAX_FREQ

		if [[ ! "$CPU_MAX_FREQ" =~ ^[0-9]+$ ]]; then
			CPU_MAX_FREQ=''
		fi
	done

	while [ -z "$MEM_BUS_SPEED" ]; do
		read -p 'What is the memory bus speed?: ' MEM_BUS_SPEED

		if [[ ! "$MEM_BUS_SPEED" =~ ^[0-9]+$ ]]; then
			MEM_BUS_SPEED=''
		fi
	done

	SCHED_TUNING="$($EXEC_SCHEDTUNER -f $CPU_MAX_FREQ -m $MEM_BUS_SPEED)"
fi

# --------------------------- Filesystem Information --------------------------

# Global Maximum Number Simultaneous Open Files
FS_FILE_MAX=$[ $RAM_TOTAL / 10 ]

# ---------------------------- Network Information ----------------------------

# Internet Download speed
INET_DL_SPEED=$($EXEC_AWK '/Download:/{ print $2 }' /etc/devops/speedtest.info)

# Internet Upload speed
INET_UL_SPEED=$($EXEC_AWK '/Upload:/{ print $2 }' /etc/devops/speedtest.info)

# ------------------------- Virtual Memory Information ------------------------

# Configure VM Dirty Ratio / VM Dirty Background Ratio / VM VFS Cache Pressure
case $RAM_GB in
[1-2])
	VM_DIRTY_RATIO=8
	VM_DIRTY_BG_RATIO=4
	VM_VFS_CACHE_PRESSURE=150
	;;
[3-4])
	VM_DIRTY_RATIO=6
	VM_DIRTY_BG_RATIO=3
	VM_VFS_CACHE_PRESSURE=125
	;;
[5-6])
	VM_DIRTY_RATIO=5
	VM_DIRTY_BG_RATIO=3
	VM_VFS_CACHE_PRESSURE=100
	;;
[7-8])
	VM_DIRTY_RATIO=4
	VM_DIRTY_BG_RATIO=2
	VM_VFS_CACHE_PRESSURE=90
	;;
[9-12])
	VM_DIRTY_RATIO=3
	VM_DIRTY_BG_RATIO=2
	VM_VFS_CACHE_PRESSURE=80
	;;
*)
	VM_DIRTY_RATIO=2
	VM_DIRTY_BG_RATIO=1
	VM_VFS_CACHE_PRESSURE=70
	;;
esac

# Configure VM Minimum Free Memory (1% of physical RAM)
VM_MIN_FREE_KB=$[ $RAM_TOTAL / 100 ]

## Template
/bin/cat << EOF
#
# sysctl.conf - DevOpsBroker Linux kernel tuning configuration file
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

#
# Linux Kernel Tuning Configuration
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

# Set the hostname of the machine
#kernel.hostname = covfefe

# Set the domain name of the host
#kernel.domainname = example.com

# Set Default Kernel Log Levels
kernel.printk = 4 4 1 7

# Enable PID Append To Kernel Core Dumps
kernel.core_uses_pid = 1

# Disable NMI Watchdog
kernel.nmi_watchdog = 0

# Set the kernel panic timeout to autoreboot
kernel.panic = 10

# Limit perf cpu time to 5%
kernel.perf_cpu_time_max_percent = 5

# Increase the PID_MAX limit
kernel.pid_max = 1048576

# Kernel Task Scheduler Optimizations
$SCHED_TUNING

# Disable Magic SysRq Key
kernel.sysrq = 0

#
# Filesystem Kernel Tuning Configuration
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

# Optimize Global Maximum Number Simultaneous Open Files
fs.file-max = $FS_FILE_MAX

#
# Network Kernel Tuning Configuration
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

$($EXEC_NETTUNER -d $INET_DL_SPEED -u $INET_UL_SPEED $NIC)

#
# Virtual Memory Kernel Tuning Configuration
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯

# Optimize VM Dirty Ratio
vm.dirty_ratio = $VM_DIRTY_RATIO

# Optimize VM Dirty Background Ratio
vm.dirty_background_ratio = $VM_DIRTY_BG_RATIO

# Optimize VM Minimum Free Memory
vm.min_free_kbytes = $VM_MIN_FREE_KB

# Do not allow Virtual Memory overcommit
vm.overcommit_memory = 2
vm.overcommit_ratio = 100

# Do not panic on Out-of-Memory condition
vm.panic_on_oom = 0

# Optimize VM Swappiness
vm.swappiness = 10

# Optimize VM VFS Cache Pressure
vm.vfs_cache_pressure = $VM_VFS_CACHE_PRESSURE

EOF

exit 0
