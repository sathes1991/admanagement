#!/bin/bash
# Deploy workstation restriction to Ubuntu PCs
# Usage: ./deploy-to-ubuntu.sh <target-ip> <username>

TARGET_IP=$1
USERNAME=$2

if [ -z "$TARGET_IP" ] || [ -z "$USERNAME" ]; then
    echo "Usage: $0 <target-ip> <username>"
    echo "Example: $0 192.168.10.101 htic"
    exit 1
fi

echo "Deploying workstation restrictions to $TARGET_IP..."

# Copy scripts to target PC
scp check-user-workstation.sh setup-workstation-restriction.sh $USERNAME@$TARGET_IP:/tmp/

# SSH and run setup
ssh $USERNAME@$TARGET_IP << 'EOF'
cd /tmp
echo "Setting up workstation restrictions..."
sudo mkdir -p /usr/local/scripts
sudo cp check-user-workstation.sh setup-workstation-restriction.sh /usr/local/scripts/
cd /usr/local/scripts
sudo bash setup-workstation-restriction.sh
echo "Setup complete on $(hostname)!"
EOF

echo "Deployment to $TARGET_IP completed!"