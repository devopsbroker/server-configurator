#!/bin/bash

#
# configure-user.sh - DevOpsBroker script for configuring users
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
# Creates the following directories for the user:
#   o $userhome/bin
#   o $userhome/.local/bin
#
# Installs the following Bash configuration files in the home directory of the
# user:
#   o .bash_aliases
#   o .bash_logout
#   o .bash_personal
#   o .bashrc
#   o .gitconfig
#   o .profile
#
# Manages the following /etc/skel configurations:
#   o /etc/skel/.bash_aliases
#   o /etc/skel/.bash_logout
#   o /etc/skel/.bash_personal
#   o /etc/skel/.bashrc
#   o /etc/skel/.gitconfig
#   o /etc/skel/.profile
#
# Adds the user to the 'users' group (if necessary)
#
# Applies stricter file and directory settings to the user's home directory
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

################################## Functions ##################################

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     createDirectory
# Description:  Creates the specified directory if it does not already exist
#
# Parameters:
#   dirName     The name of the directory to create
#   mode        The file mode to set on the directory (defaults to 0750)
# -----------------------------------------------------------------------------
function createDirectory() {
	local dirName="$1"
	local mode=${2:-'0750'}

	if [ ! -d "$dirName" ]; then
		printInfo "Creating $dirName directory"

		$EXEC_MKDIR --parents --mode=$mode "$dirName"
		$EXEC_CHOWN --changes $username:$username "$dirName"
	fi
}

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     installHomeConfig
# Description:  Installs the configuration file into the $userhome directory
#
# Parameter $1: Name of the configuration file to install
# Parameter $2: Name of the source configuration file
# -----------------------------------------------------------------------------
function installHomeConfig() {
	local configFile="$1"
	local sourceFile="$2"

	if [ ! -f "$userhome/$configFile" ] || ! $EXEC_GREP -Fq 'DevOpsBroker' "$userhome/$configFile"; then
		printInfo "Installing $userhome/$configFile"

		# Install as $username:$username with rw-r----- privileges
		$EXEC_INSTALL -b --suffix .orig -o $username -g $username -m 640 "$SCRIPT_DIR/$sourceFile" "$userhome/$configFile"

	elif [ "$SCRIPT_DIR/$sourceFile" -nt "$userhome/$configFile" ]; then
		printInfo "Updating $userhome/$configFile"

		# Install as $username:$username with rw-r----- privileges
		$EXEC_INSTALL -b --suffix .bak -o $username -g $username -m 640 "$SCRIPT_DIR/$sourceFile" "$userhome/$configFile"
	fi
}

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     installSkeleton
# Description:  Installs the user configuration file into the /etc/skel directory
#
# Parameter $1: Name of the configuration file to install
# Parameter $2: Name of the /etc/skel file
# -----------------------------------------------------------------------------
function installSkeleton() {
	if [ ! -f "/etc/skel/$2" ] || [ "$SCRIPT_DIR/$1" -nt "/etc/skel/$2" ]; then
		printInfo "Installing /etc/skel/$2"

		# Install as root:root with rw-r--r-- privileges
		$EXEC_INSTALL -o root -g root -m 644 "$SCRIPT_DIR/$1" "/etc/skel/$2"
	fi
}

################################## Variables ##################################

## Options
username=${1:-$SUDO_USER}

## Variables
export TMPDIR=${TMPDIR:-'/tmp'}

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

userRecord="$($EXEC_GETENT passwd $username)"

# Ensure the argument is a valid username
if [ ${#userRecord} -eq 0 ]; then
	printError "$SCRIPT_EXEC" "Cannot find '$username': No such user"
	echo
	printUsage "$SCRIPT_EXEC USER"

	exit 1
fi

IFS=':'; userInfo=($userRecord); IFS=$'\n\t'

# Ensure the user is using bash for the shell
if [ "${userInfo[6]}" != '/bin/bash' ]; then
	printError "$SCRIPT_EXEC" "User shell not bash: ${userInfo[6]}"
	exit 1
fi

userhome="${userInfo[5]}"

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE User Configurator" 'true'

# Create user directories
createDirectory "$userhome/bin"
createDirectory "$userhome/.local/bin"
createDirectory "$userhome/.config/systemd/user"

# Install $userhome/.bash_aliases
installHomeConfig '.bash_aliases' 'bash_aliases'

# Install $userhome/.bash_logout
installHomeConfig '.bash_logout' 'bash_logout'

# Install $userhome/.bash_personal
if [ ! -f "$userhome"/.bash_personal ]; then
	printInfo "Installing $userhome/.bash_personal"

	# Install as $username:$username with rw-r----- privileges
	$EXEC_INSTALL -o $username -g $username -m 640 "$SCRIPT_DIR"/bash_personal "$userhome"/.bash_personal
fi

# Install $userhome/.bashrc
installHomeConfig '.bashrc' 'bashrc'

# Install $userhome/.gitconfig
installHomeConfig '.gitconfig' 'gitconfig'

# Install $userhome/.profile
installHomeConfig '.profile' 'profile'

# Install /etc/skel/.bash_aliases
installSkeleton 'bash_aliases' '.bash_aliases'

# Install /etc/skel/.bash_logout
installSkeleton 'bash_logout' '.bash_logout'

# Install /etc/skel/.bash_personal
installSkeleton 'bash_personal' '.bash_personal'

# Install /etc/skel/.bashrc
installSkeleton 'bashrc' '.bashrc'

# Install /etc/skel/.gitconfig
installSkeleton 'gitconfig' '.gitconfig'

# Install /etc/skel/.profile
installSkeleton 'profile' '.profile'

userGroups=$( $EXEC_GROUPS $username )

# Add $username to the 'users' group
regExpr="\\busers\\b"
if [[ ! "$userGroups" =~ $regExpr ]]; then
	printInfo "Adding $username to the 'users' group"

	$EXEC_ADDUSER $username 'users'
fi

#
# Apply stricter file and directory settings
#

printInfo "Changing any root:root files and directories to '$username:$username'"

$EXEC_FIND "$userhome" -xdev -user root -group root -execdir $EXEC_CHOWN --changes $username:$username {} +

printInfo "Applying stricter directory security settings to $userhome"

# Configure all hidden directories with drwx------ privileges
$EXEC_FIND "$userhome" -xdev -maxdepth 1 -type d -path "$userhome/.*" -perm /077 -exec $EXEC_CHMOD --changes 700 {} +

# Configure all normal directories with drwxr-x--- privileges
$EXEC_FIND "$userhome" -xdev -type d -perm /027 -exec $EXEC_CHMOD --changes 750 {} + 2>/dev/null

printInfo "Applying stricter file security settings to $userhome"

# Remove ----w-rwx file privileges
$EXEC_FIND "$userhome" -xdev -type d \( -name ".git" -o -name ".svn" \) -prune -o -type f -perm /027 -exec $EXEC_CHMOD --changes g-w,o-rwx {} +

echo

exit 0
