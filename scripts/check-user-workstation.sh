#!/bin/bash
# Script to check if user is allowed to login from current workstation
# Based on AD userWorkstations attribute
# 
# Usage: This script should be called from PAM or SSH configuration
# 
# Deploy this to: /usr/local/bin/check-user-workstation.sh
# Make executable: chmod +x /usr/local/bin/check-user-workstation.sh

# Configuration
AD_SERVER="192.168.10.80"
AD_DOMAIN="vvs.com"
BASE_DN="DC=vvs,DC=com"

# Get parameters
USER=$1
CLIENT_IP=$2
CLIENT_HOSTNAME=$3

# Get current hostname if not provided
if [ -z "$CLIENT_HOSTNAME" ]; then
    CLIENT_HOSTNAME=$(hostname)
fi

# Exit codes
EXIT_ALLOW=0
EXIT_DENY=1

# Function to log messages
log_message() {
    logger -t "workstation-check" "$1"
}

# Check if required parameters are provided
if [ -z "$USER" ]; then
    log_message "ERROR: Username not provided"
    exit $EXIT_DENY
fi

# Get current hostname if not provided
if [ -z "$CLIENT_HOSTNAME" ]; then
    CLIENT_HOSTNAME=$(hostname)
fi

log_message "Checking workstation access for user: $USER from host: $CLIENT_HOSTNAME"

# Use ldapsearch to query AD for userWorkstations attribute
# Note: This requires ldap-utils package and proper authentication
# Try with different authentication methods for better compatibility
LDAP_RESULT=$(ldapsearch -x -H "ldap://$AD_SERVER:389" \
    -D "ldap-reader@$AD_DOMAIN" \
    -w "Health#123" \
    -b "OU=LinuxUsers,$BASE_DN" \
    "(sAMAccountName=$USER)" userWorkstations 2>&1)

# Debug: Log the full LDAP result
log_message "DEBUG: LDAP query result: $LDAP_RESULT"

# Extract userWorkstations value
ALLOWED_WORKSTATIONS=$(echo "$LDAP_RESULT" | grep "userWorkstations:" | sed 's/userWorkstations: //' | tr -d '\n')

# If no userWorkstations attribute is set, allow access (default behavior)
if [ -z "$ALLOWED_WORKSTATIONS" ]; then
    log_message "No workstation restrictions found for user $USER - allowing access"
    exit $EXIT_ALLOW
fi

# Debug: Log what we found
log_message "DEBUG: Raw userWorkstations value: '$ALLOWED_WORKSTATIONS'"
log_message "DEBUG: Current hostname: '$CLIENT_HOSTNAME'"

# Check if current hostname is in the allowed list
if echo "$ALLOWED_WORKSTATIONS" | grep -qi "$CLIENT_HOSTNAME"; then
    log_message "Access ALLOWED for user $USER from workstation $CLIENT_HOSTNAME"
    exit $EXIT_ALLOW
else
    log_message "Access DENIED for user $USER from workstation $CLIENT_HOSTNAME (allowed: $ALLOWED_WORKSTATIONS)"
    exit $EXIT_DENY
fi