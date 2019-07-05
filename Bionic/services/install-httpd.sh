#!/bin/bash

#
# install-httpd.sh - DevOpsBroker installation script for Apache httpd service
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
# Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-21
#
# This script was derived from the tutorial found on DigitalOcean at:
#   o https://www.digitalocean.com/community/tutorials/how-to-install-the-apache-web-server-on-ubuntu-18-04-quickstart
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

# Load /etc/devops/functions-admin.conf if FUNC_ADMIN_CONFIG is unset
if [ -z "$FUNC_ADMIN_CONFIG" ] && [ -f /etc/devops/functions-admin.conf ]; then
	source /etc/devops/functions-admin.conf
fi

${FUNC_ADMIN_CONFIG?"[1;91mCannot load '/etc/devops/functions-admin.conf': No such file[0m"}

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
EXEC_A2ENMOD=/usr/sbin/a2enmod
EXEC_A2ENSITE=/usr/sbin/a2ensite
EXEC_A2DISSITE=/usr/sbin/a2dissite
EXEC_APACHE2CTL=/usr/sbin/apache2ctl
EXEC_DNSDOMAINNAME=/bin/dnsdomainname
EXEC_FIREWALL=/usr/local/sbin/firewall

## Options

## Variables
DNS_NAME="$($EXEC_DNSDOMAINNAME)"

################################### Actions ###################################

# Clear screen only if called from command line
if [ $SHLVL -eq 1 ]; then
	clear
fi

printBox "DevOpsBroker $UBUNTU_RELEASE Apache httpd Installer" 'true'

#
# Configure Website domain
#

read -p "${bold}${green}Which domain will this website serve? ${reset}" -i "$DNS_NAME" -e DNS_NAME

while [ -z "$DNS_NAME" ]; do
	read -p "${bold}${green}Which domain will this website serve? ${reset}" -i "$DNS_NAME" -e DNS_NAME
done

# Exit if /etc/apache2/sites-available/${DNS_NAME}.conf already configured
if [ -f /etc/apache2/sites-available/${DNS_NAME}.conf ]; then
	printInfo "/etc/apache2/sites-available/${DNS_NAME}.conf already configured"
	echo
	exit 0
fi

echo

echo "${bold}${green}Will this website use CGI scripts? ${white}"
select cgiOption in 'Yes' 'No'; do
	if [ "$cgiOption" == 'Yes' ]; then
		cgiOption='+ExecCGI'
		break;
	elif [ "$cgiOption" == 'No' ]; then
		cgiOption='-ExecCGI'
		break;
	fi
done

echo

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Installation ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#
# Install Apache2 HTTPD server and mod-security module with OWASP ModSecurity Core Rule Set
#
printBanner 'Installing apache2'
$EXEC_APT -y install apache2
echo

printBanner 'Installing libapache2-mod-security2'
$EXEC_APT -y install libapache2-mod-security2
echo

printBanner 'Installing modsecurity-crs'
$EXEC_APT -y install modsecurity-crs
echo

#
# Install Apache2 Global and Security configuration files
#
installConfig 'apache2.conf' "$SCRIPT_DIR/etc/apache2" /etc/apache2
installConfig 'security.conf' "$SCRIPT_DIR/etc/apache2/conf-available" /etc/apache2/conf-available

#
# Enable mod_headers / mod_http2 / mod_security / mod_ssl
#
printInfo 'Enabling mod_headers'
$EXEC_A2ENMOD headers

printInfo 'Enabling mod_http2'
$EXEC_A2ENMOD http2

printInfo 'Enabling mod_security'
$EXEC_A2ENMOD security2

printInfo 'Enabling mod_ssl'
$EXEC_A2ENMOD ssl

# Enable httpd firewall settings
printBanner 'Enabling httpd firewall settings'
$EXEC_FIREWALL enable httpd
echo

# Create Virtual Host directory
if [ ! -d /var/www/${DNS_NAME}/html ]; then
	printInfo "Creating Virtual Host directory /var/www/${DNS_NAME}/html"
	$EXEC_MKDIR --parents /var/www/${DNS_NAME}/html
fi

# Generate sample index.html
printInfo 'Generating sample index.html'

/bin/cat << EOF > /var/www/${DNS_NAME}/html/index.html
<html>
<head>
	<title>Welcome to ${DNS_NAME}!</title>
</head>
<body>
	<h1>Success! The ${DNS_NAME} Virtual Host is operational!</h1>
</body>
</html>

EOF

# Generate default robots.txt file to block all web crawling
printInfo 'Generating default robots.txt'

/bin/cat << EOF > /var/www/${DNS_NAME}/html/robots.txt
User-agent: *
Disallow: *

EOF

# Generate Virtual Host configuration block
printInfo 'Generating Virtual Host configuration block'

/bin/cat << EOF > /etc/apache2/sites-available/${DNS_NAME}.conf
<VirtualHost *:80>
    Options ${cgiOption}
    ServerAdmin admin@${DNS_NAME}
    ServerName ${DNS_NAME}
    ServerAlias www.${DNS_NAME}
    DocumentRoot /var/www/${DNS_NAME}/html
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

#<VirtualHost *:443>
#    Options ${cgiOption}
#    ServerAdmin admin@${DNS_NAME}
#    ServerName ${DNS_NAME}
#    ServerAlias www.${DNS_NAME}
#    DocumentRoot /var/www/${DNS_NAME}/html
#    ErrorLog \${APACHE_LOG_DIR}/error.log
#    CustomLog \${APACHE_LOG_DIR}/access.log combined
#    SSLEngine on
#    SSLCertificateKeyFile /etc/ssl/private/private.pem
#    SSLCertificateFile /etc/ssl/certs/cert.pem
#    Protocols h2 http/1.1
#</VirtualHost>

EOF

# Update file and directory security
printInfo 'Updating file and directory security'
$EXEC_CHOWN --changes -R $SUDO_USER:$SUDO_USER /var/www/${DNS_NAME}/html
$EXEC_CHMOD --changes -R 755 /var/www/${DNS_NAME}

# Enable new Virtual Host configuration block
printInfo "Enabling ${DNS_NAME} Virtual Host"
$EXEC_A2ENSITE ${DNS_NAME}.conf

# Disabling default site configuration block
printInfo 'Disabling default site configuration'
$EXEC_A2DISSITE 000-default.conf

# Test for configuration errors
printInfo 'Testing for configuration errors'
$EXEC_APACHE2CTL configtest

# Restart apache2 service
printInfo 'Restarting apache2 service'
$EXEC_SYSTEMCTL restart apache2

echo

printNotice $SCRIPT_EXEC 'Remember to add/update your DNS records!!!'
printNotice $SCRIPT_EXEC 'Remember to update robots.txt when ready for production!!!'

echo

exit 0
