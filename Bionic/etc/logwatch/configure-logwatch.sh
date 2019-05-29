#!/bin/bash

#
# configure-logwatch.sh - DevOpsBroker administration script for configuring LogWatch
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
# Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-16
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

## Variables
YEAR=$($EXEC_DATE +'%Y')
EMAIL_ADDRESS=''

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE LogWatch Configurator" 'true'

# Exit if /usr/share/logwatch/default.conf/logwatch.conf already configured
set +o errexit
if [ -f /usr/share/logwatch/default.conf/logwatch.conf ] && [ "$( $EXEC_GREP -F --max-count=1 'DevOpsBroker' /usr/share/logwatch/default.conf/logwatch.conf )" ] && [ "${1:-}" != '-f' ]; then
	printInfo '/usr/share/logwatch/default.conf/logwatch.conf already configured'
	echo
	printUsage "$SCRIPT_EXEC ${gold}[-f]"

	echo ${bold}
	echo "Valid Options:${romantic}"
	echo -e ${gold}'  -f\t'  ${romantic}'Force /usr/share/logwatch/default.conf/logwatch.conf reconfiguration'
	echo ${reset}

	exit 0
fi
set -o errexit

#
# Configure MailTo email address
#

read -p "${bold}${green}What email address do you want LogWatch reports mailed to?: ${reset}" -i "$EMAIL_ADDRESS" -e EMAIL_ADDRESS

while [ -z "$EMAIL_ADDRESS" ]; do
	read -p "${bold}${green}What email address do you want LogWatch reports mailed to?: ${reset}" -i "$EMAIL_ADDRESS" -e EMAIL_ADDRESS
done

echo

#
# Generate logwatch.conf
#

printInfo 'Generating /usr/share/logwatch/default.conf/logwatch.conf'

/bin/cat << EOF > /usr/share/logwatch/default.conf/logwatch.conf
#
# logwatch.conf - DevOpsBroker configuration for LogWatch
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
# Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-16
#
# The following rules apply when setting configuration values:
#   o Format is in the form of <name> = <value>
#   o Whitespace at the beginning and end of the lines is removed
#   o Whitespace before and after the = sign is removed
#   o Everything is case *insensitive*
#   o Yes = True = On = 1
#   o No = False = Off = 0
# -----------------------------------------------------------------------------
#

# Default Log Directory
# All log-files are assumed to be given relative to this directory.
LogDir = /var/log

# You can override the default temp directory (/tmp) here
TmpDir = /var/cache/logwatch

# Output/Format Options
Output = mail                                              # (stdout, file)
Format = html                                              # (text)
Encode = none                                              # (base64)

# Default person to mail reports to.  Can be a local account or a
# complete email address.  Variable Output should be set to mail, or
# --output mail should be passed on command line to enable mail feature.
MailTo = ${EMAIL_ADDRESS}

# WHen using option --multiemail, it is possible to specify a different
# email recipient per host processed.  For example, to send the report
# for hostname host1 to user@example.com, use:
#Mailto_host1 = user@example.com
# Multiple recipients can be specified by separating them with a space.

# Default person to mail reports from.  Can be a local account or a
# complete email address.
MailFrom = Logwatch

# if set, the results will be saved in <filename> instead of mailed
# or displayed. Be sure to set Output = file also.
#Filename = /tmp/logwatch

# Use archives?  If set to 'Yes', the archives of logfiles
# (i.e. /var/log/messages.1 or /var/log/messages.1.gz) will
# be searched in addition to the /var/log/messages file.
# This usually will not do much if your range is set to just
# 'Yesterday' or 'Today'... it is probably best used with Range = All
# By default this is now set to Yes. To turn off Archives uncomment this.
#Archives = No

# Report Time Range
Range = yesterday                                          # (all, today)

# Report Detail Level
Detail = Med                                               # (Low, High, 0-10)

# The 'Service' option expects either the name of a filter
# (in /usr/share/logwatch/scripts/services/*) or 'All'.
# The default service(s) to report on.  This should be left as All for
# most people.
Service = All
# You can also disable certain services (when specifying all)
#Service = "-zz-network"     # Prevents execution of zz-network service, which
#                            # prints useful network configuration info.
#Service = "-zz-sys"         # Prevents execution of zz-sys service, which
#                            # prints useful system configuration info.
#Service = "-eximstats"      # Prevents execution of eximstats service, which
#                            # is a wrapper for the eximstats program.
# If you only cared about FTP messages, you could use these 2 lines
# instead of the above:
#Service = ftpd-messages   # Processes ftpd messages in /var/log/messages
#Service = ftpd-xferlog    # Processes ftpd messages in /var/log/xferlog
# Maybe you only wanted reports on PAM messages, then you would use:
#Service = pam_pwdb        # PAM_pwdb messages - usually quite a bit
#Service = pam             # General PAM messages... usually not many

# You can also choose to use the 'LogFile' option.  This will cause
# logwatch to only analyze that one logfile.. for example:root
#LogFile = messages
# will process /var/log/messages.  This will run all the filters that
# process that logfile.  This option is probably not too useful to
# most people.  Setting 'Service' to 'All' above analyzes all LogFiles
# anyways...

#
# By default we assume that all Unix systems have sendmail or a sendmail-like MTA.
# The mailer code prints a header with To: From: and Subject:.
# At this point you can change the mailer to anything that can handle this output
# stream.
# TODO test variables in the mailer string to see if the To/From/Subject can be set
# From here with out breaking anything. This would allow mail/mailx/nail etc..... -mgt
mailer = "/usr/sbin/sendmail -t"

#
# With this option set to a comma separted list of hostnames, only log entries
# for these particular hosts will be processed.  This can allow a log host to
# process only its own logs, or Logwatch can be run once per a set of hosts
# included in the logfiles.
# Example: HostLimit = hosta,hostb,myhost
#
# The default is to report on all log entries, regardless of its source host.
# Note that some logfiles do not include host information and will not be
# influenced by this setting.
#
#HostLimit = myhost

EOF

echo

exit 0
