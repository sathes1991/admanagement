#!/bin/bash
# Setup script to configure workstation restrictions on Ubuntu PCs
# This script blocks ALL login methods: SSH, Desktop, Console, etc.
# Run as root on each Ubuntu PC

echo "Setting up comprehensive AD workstation restrictions for ALL login methods..."

# Install required packages
apt update
apt install -y ldap-utils

# Copy the check script
cp check-user-workstation.sh /usr/local/bin/
chmod +x /usr/local/bin/check-user-workstation.sh

# Create PAM script wrapper
cat > /usr/local/bin/pam-workstation-check.sh << 'EOF'
#!/bin/bash
# PAM wrapper for workstation checking - blocks ALL login methods

# Get the username from PAM environment
USER="$PAM_USER"
# Get client IP from SSH connection (if available)
CLIENT_IP="$PAM_RHOST"
# Get current hostname
CLIENT_HOSTNAME=$(hostname)

# Log the login attempt
logger -t "workstation-auth" "Login attempt by user: $USER from service: $PAM_SERVICE on host: $CLIENT_HOSTNAME"

# Call the main check script
/usr/local/bin/check-user-workstation.sh "$USER" "$CLIENT_IP" "$CLIENT_HOSTNAME"
exit $?
EOF

chmod +x /usr/local/bin/pam-workstation-check.sh

# Configure PAM for ALL login methods
echo "Configuring PAM for comprehensive workstation restrictions..."

# List of PAM files to modify for complete coverage
PAM_FILES=(
    "/etc/pam.d/sshd"           # SSH access
    "/etc/pam.d/login"          # Console login
    "/etc/pam.d/gdm-auth"       # GNOME Display Manager (Ubuntu Desktop)
    "/etc/pam.d/lightdm"        # LightDM (alternative desktop manager)
    "/etc/pam.d/common-account" # Common account validation
    "/etc/pam.d/su"             # Switch user
    "/etc/pam.d/sudo"           # Sudo access
)

# Add workstation check to each PAM file
for pam_file in "${PAM_FILES[@]}"; do
    if [ -f "$pam_file" ]; then
        if ! grep -q "pam_exec.*workstation" "$pam_file"; then
            echo "# AD Workstation restriction check" >> "$pam_file"
            echo "account required pam_exec.so /usr/local/bin/pam-workstation-check.sh" >> "$pam_file"
            echo "Added workstation check to $pam_file"
        else
            echo "Workstation check already present in $pam_file"
        fi
    else
        echo "Warning: $pam_file not found, skipping..."
    fi
done

# Create a systemd service to check at login
cat > /etc/systemd/system/workstation-check.service << 'EOF'
[Unit]
Description=AD Workstation Access Check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/check-user-workstation.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable the service
systemctl daemon-reload
systemctl enable workstation-check.service

# Restart services
echo "Restarting authentication services..."
systemctl restart sshd
systemctl restart gdm 2>/dev/null || systemctl restart lightdm 2>/dev/null || echo "No display manager to restart"

# Create a test script
cat > /usr/local/bin/test-workstation-restriction.sh << 'EOF'
#!/bin/bash
# Test script to verify workstation restrictions

echo "Testing workstation restrictions..."
echo "Current hostname: $(hostname)"
echo "Testing for user: $1"

if [ -z "$1" ]; then
    echo "Usage: $0 <username>"
    exit 1
fi

/usr/local/bin/check-user-workstation.sh "$1" "" "$(hostname)"
result=$?

if [ $result -eq 0 ]; then
    echo "✅ User $1 is ALLOWED to login on this workstation"
else
    echo "❌ User $1 is DENIED login on this workstation"
fi
EOF

chmod +x /usr/local/bin/test-workstation-restriction.sh

echo ""
echo "🎯 Setup complete! Workstation restrictions are now active for:"
echo "   ✅ SSH login"
echo "   ✅ Desktop login (GDM/LightDM)"
echo "   ✅ Console login (TTY)"
echo "   ✅ Su/Sudo access"
echo ""
echo "📝 Next steps:"
echo "   1. Edit /usr/local/bin/check-user-workstation.sh"
echo "   2. Configure your service account credentials"
echo "   3. Test with: /usr/local/bin/test-workstation-restriction.sh <username>"
echo ""
echo "⚠️  IMPORTANT: Make sure to test thoroughly before deploying to production!"