#!/bin/bash

#
# tune-diskio.tpl - DevOpsBroker template for configuring disk I/O parameters
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

################################## Variables ##################################

## Bash exec variables
EXEC_HDPARM=/sbin/hdparm
EXEC_LSBLK=/bin/lsblk
EXEC_UDEVADM=/sbin/udevadm

## Options
deviceNode="$1"

## Variables
export TMPDIR=${TMPDIR:-'/tmp'}
YEAR=$($EXEC_DATE +'%Y')

ioPoll=1
ncqPrioEnable=0
rqAffinity=2

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Display usage if no parameters given
if [ -z "$deviceNode" ]; then
	printUsage "$SCRIPT_EXEC DEVICE_NODE"
	exit 1
fi

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Gather Serial Number, Device Transport Type, and Device Type
IFS=' '; attributeList=($($EXEC_LSBLK -dn --output KNAME,SERIAL,TYPE $deviceNode 2>/dev/null)); IFS=$'\n\t'

deviceName=${attributeList[0]}

if [ ! -L "/sys/block/$deviceName" ]; then
	printError "$SCRIPT_EXEC" "Cannot tune '$deviceNode': Not a block device"
	echo
	printUsage "$SCRIPT_EXEC DEVICE_NODE"

	exit 1
fi

if [[ "$deviceName" == nvme* ]]; then
	printInfo 'No configuration necessary for an NVMe device'
	exit 0
fi

if [[ "$deviceName" == sr* ]]; then
	printInfo 'No configuration necessary for a CD/DVD/BD-ROM device'
	exit 0
fi

# Initialize variables
isRemovable=$($EXEC_CAT "/sys/block/$deviceName/removable")
isRotational=$($EXEC_CAT "/sys/block/$deviceName/queue/rotational")
modelName=$($EXEC_CAT "/sys/block/$deviceName/device/model")
serialNumber=${attributeList[1]}
udevRuleFile="65-diskio-${serialNumber}.rules"

# Execute sequential read benchmark
if [ ! -f /etc/devops/diskio-${serialNumber}.info ]; then
	printInfo "Executing $deviceNode sequential read benchmark"
	$EXEC_HDPARM -t $deviceNode | tee /etc/devops/diskio-${serialNumber}.info
	echo
fi

# Load disk I/O benchmark data
diskIOBench=($($EXEC_CAT /etc/devops/diskio-${serialNumber}.info))
diskSpeed=${diskIOBench[11]::-3}
diskMetric=${diskIOBench[12]}

# Calculate read_ahead_kb value
if [ "$diskMetric" == 'MB/sec' ]; then
	diskSpeed=$[ $diskSpeed * 1048576 ]
	readAheadKB=$[ $diskSpeed / 65536000 * 64 ]
	readAheadKB=$( max $readAheadKB 64 )
fi

# Calculate nrRequests value
nrRequests=$( min $[ $diskSpeed / 512000 ] 2048 )

# Set the max_sectors_kb equal to the max_hw_sectors_kb value
maxSectorsKB=$($EXEC_CAT /sys/block/$deviceName/queue/max_hw_sectors_kb)

# Calculate read_lat_nsec/write_lat_nsec values for kyber
if [ "$isRotational" == '1' ] && [[ "$modelName" =~ Flash.?Drive ]]; then
	isRotational=0
fi

if [ "$isRotational" == '0' ]; then
	nanoSecLat=$[ 1000000000 / ($diskSpeed / 1000) ]
else
	# Calculate the disk size
	diskSize=$($EXEC_CAT /sys/block/$deviceName/size)
	hwSectorSize=$($EXEC_CAT /sys/block/$deviceName/queue/hw_sector_size)
	diskSize=$[ $diskSize * $hwSectorSize ]

	# Calculate back_seek_max and set back_seek_penalty
	backSeekMax=$[ $diskSize / 5120000 ]
	backSeekPenalty=2

	# Calculate fifo_expire_async, fifo_expire_sync, and timeout_sync
	fifoExpireAsync=$[ ($maxSectorsKB * 1024000) / $diskSpeed ]
	fifoExpireAsync=$[ $fifoExpireAsync * 3 / 2 ]
	fifoExpireSync=$[ $fifoExpireAsync / 2 ]
	timeoutSync=$[ $fifoExpireSync - 1 ]

	# Set low_latency and max_budget
	lowLatency=1
	maxBudget=$[ ($maxSectorsKB * 1024) / $hwSectorSize ]

	# Calculate slice_idle and slice_idle_us
	sliceIdle=0
	sliceIdleUS=$[ 240000000000 / $diskSpeed ]
fi

# Enable NCQ prioritization
if [ -f "/sys/block/$deviceName/device/ncq_prio_enable" ]; then
	ncqPrioEnable=1
fi

# Retrieve the device path
devPath=$($EXEC_UDEVADM info -q path -n $deviceNode)
scsiDriverKernel=$($EXEC_BASENAME $($EXEC_DIRNAME $($EXEC_DIRNAME $devPath)))

## Template
/bin/cat << EOF > "$TMPDIR"/$udevRuleFile
#
# $udevRuleFile
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
# Developed on Ubuntu 18.04.1 LTS running kernel.osrelease = 4.15.0-45
#
# -----------------------------------------------------------------------------
#

# Disk I/O settings for $serialNumber
ENV{ID_SERIAL_SHORT}!="$serialNumber", GOTO="disk-io-settings-end"
ACTION!="add", GOTO="disk-io-settings-end"
ENV{DEVTYPE}!="disk", GOTO="disk-io-settings-end"

EOF

if [ "$isRotational" == '0' ]; then
/bin/cat << EOF >> "$TMPDIR"/$udevRuleFile
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/read_lat_nsec}="$nanoSecLat"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/write_lat_nsec}="$nanoSecLat"

EOF

else
/bin/cat << EOF >> "$TMPDIR"/$udevRuleFile
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/back_seek_max}="$backSeekMax"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/back_seek_penalty}="$backSeekPenalty"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/fifo_expire_async}="$fifoExpireAsync"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/fifo_expire_sync}="$fifoExpireSync"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/low_latency}="$lowLatency"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/max_budget}="$maxBudget"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/slice_idle}="$sliceIdle"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/slice_idle_us}="$sliceIdleUS"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/iosched/timeout_sync}="$timeoutSync"

EOF

fi

/bin/cat << EOF >> "$TMPDIR"/$udevRuleFile
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/io_poll}="$ioPoll"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/max_sectors_kb}="$maxSectorsKB"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/nr_requests}="$nrRequests"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/read_ahead_kb}="$readAheadKB"
KERNEL=="sd[a-z]", SUBSYSTEM=="block", ATTR{queue/rq_affinity}="$rqAffinity"

KERNELS=="$scsiDriverKernel", SUBSYSTEMS=="scsi", DRIVERS=="sd", ATTR{ncq_prio_enable}="$ncqPrioEnable"

LABEL="disk-io-settings-end"

EOF

# Install as root:root with rw-r--r-- privileges
$EXEC_INSTALL -b --suffix .bak -o root -g root -m 644 "$TMPDIR/$udevRuleFile" /etc/udev/rules.d/

$EXEC_RM "$TMPDIR/$udevRuleFile"

exit 0
