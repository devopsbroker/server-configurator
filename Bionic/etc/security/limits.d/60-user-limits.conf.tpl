#!/bin/bash

#
# 60-user-limits.conf.tpl - DevOpsBroker script for generating /etc/security/limits.d/60-user-limits.conf
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
# Display user limits:
#   o ulimit -a
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

# Display error if not running as root
if [ "$USER" != 'root' ]; then
	printError '60-user-limits.conf.tpl' 'Permission denied (you must be root)'
	exit 1
fi

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Robustness ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

set -o errexit                 # Exit if any statement returns a non-true value
set -o nounset                 # Exit if use an uninitialised variable

################################## Variables ##################################

## Configuration
RAM_TOTAL=$(getRamTotal)

## Variables
YEAR=$($EXEC_DATE +'%Y')

# Global Maximum Locked-in-Memory Address Space (KB)
MEMLOCK_MAX_SOFT=$[ $RAM_TOTAL / 4 ]
MEMLOCK_MAX_HARD=$[ $RAM_TOTAL / 2 ]

# Global Maximum Number Simultaneous Open Files
FS_FILE_MAX=$[ $RAM_TOTAL / 10 ]
USER_FILE_MAX_SOFT=$[ $FS_FILE_MAX / 4 ]
USER_FILE_MAX_HARD=$[ $FS_FILE_MAX / 2 ]

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## Template
/bin/cat << EOF
#
# 60-user-limits.conf - DevOpsBroker configuration for user limits (bash ulimit)
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
# See bash(1) for more information on the ulimit command and its available
# options.
# -----------------------------------------------------------------------------
#

# <domain>      <type>  <item>          <value>

# Sets the core file size limit to 128MB/256MB for all users (except root)
*               soft    core            131072
*               hard    core            262144

# Set maximum locked-in-memory address space (KB) for all users (except root)
*               soft    memlock         $MEMLOCK_MAX_SOFT
*               hard    memlock         $MEMLOCK_MAX_HARD

# Set maximum number of open files for all users
*               soft    nofile          $USER_FILE_MAX_SOFT
*               hard    nofile          $USER_FILE_MAX_HARD
root            soft    nofile          $USER_FILE_MAX_HARD
root            hard    nofile          $USER_FILE_MAX_HARD

EOF
