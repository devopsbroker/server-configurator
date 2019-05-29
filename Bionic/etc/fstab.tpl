#!/bin/bash

#
# fstab.tpl - DevOpsBroker template for generating /etc/fstab configuration
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
# Useful Linux Command-Line Utilities
# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Find a filesystem:
#   o findmnt
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

scriptName='fstab.tpl'

# Display error if not running as root
if [ "$USER" != 'root' ]; then
	printError $scriptName 'Permission denied (you must be root)'
	exit 1
fi

################################## Functions ##################################

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     printEntryList
# Description:  Prints the /etc/fstab entry list for the template
# -----------------------------------------------------------------------------
function printEntryList() {
	for fstabEntry in "${fstabOutputList[@]}"; do
		echo -e "$fstabEntry"
	done
}

################################## Variables ##################################

## Variables
YEAR=$($EXEC_DATE +'%Y')
fstabOutputList=()
index=0

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Load current /etc/fstab settings
mapfile -t fstabEntryList < <($EXEC_CAT /etc/fstab)

lineNum=0
numEntries=${#fstabEntryList[@]}
for fstabEntry in "${fstabEntryList[@]}"; do
	lineNum=$[ lineNum + 1 ]

	if [[ "$fstabEntry" =~ ^(# <file system>) ]]; then
		index=$lineNum
		break;
	fi
done

# Process /etc/fstab entries
for (( i=$index; i<$numEntries; i++ )); do
	fstabEntry="${fstabEntryList[i]}"

	if [[ "$fstabEntry" =~ ^# ]]; then
		fstabOutputList+=( "$fstabEntry" )
	else
		unset IFS; entryList=( $fstabEntry ); IFS=$'\n\t'

		entry="${entryList[0]}"
		entryLength=${#entry}
		while [ $entryLength -lt 40 ]; do
			entry="$entry\t"
			entryLength=$(( (($entryLength + 8) / 8) * 8 ))
		done

		if [ $entryLength -eq 40 ]; then
			entry="$entry "
			entryLength=$((entryLength + 1))
		fi

		entry="$entry ${entryList[1]}"
		entryLength=$((entryLength + ${#entryList[1]} + 1))

		if [ "$entryLength" -lt 48 ]; then
			entry="$entry\t\t  ${entryList[2]}"
		else
			entry="$entry\t  ${entryList[2]}"
		fi

		entryLength=$(( 58 + ${#entryList[2]} ))

		if [ "$entryLength" -lt 64 ]; then
			entry="$entry\t\t"
		else
			entry="$entry\t"
		fi

		entryLength=72

		if [ "${entryList[3]}" == 'defaults' ]; then
			if [ "${entryList[1]}" == '/tmp' ]; then
				entry="${entry}nosuid,nodev,noatime"
				entryLength=$(( entryLength + 56 ))
			else
				entry="${entry}defaults,noatime"
				entryLength=$(( entryLength + 16 ))
			fi
		else
			entry="$entry${entryList[3]}"
			entryLength=$(( entryLength + ${#entryList[3]} ))
		fi

		while [ $entryLength -lt 96 ]; do
			entry="$entry\t"
			entryLength=$(( (($entryLength + 8) / 8) * 8 ))
		done

		if [ $entryLength -gt 96 ]; then
			entry="$entry\t${entryList[4]}"
		else
			entry="$entry${entryList[4]}"
		fi

		entry="$entry\t${entryList[5]}"

		fstabOutputList+=( "$entry" )
	fi
done

## Template
/bin/cat << EOF
#
# fstab - DevOpsBroker /etc/fstab configuration
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
# Use 'blkid' to print the universally unique identifier for a device; this may
# be used with UUID= as a more robust way to name devices that works even if
# disks are added and removed. See fstab(5).
# -----------------------------------------------------------------------------
#

# <file system>				  <mount point>   <type>	<options>		<dump>	<pass>
$(printEntryList)

EOF

exit 0
