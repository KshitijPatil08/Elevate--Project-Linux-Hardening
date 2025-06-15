#!/bin/bash
echo "Starting Linux Hardening Script..."

# 1. Update System Packages
apt update && apt upgrade -y

# 2. Disable Unused Services
systemctl disable bluetooth.service
systemctl disable cups.service
systemctl disable avahi-daemon.service

# 3. Enforce Password Policy
sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10' /etc/login.defs
sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs

# 4. Set Permissions on Important Files
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 600 /boot/grub/grub.cfg 2>/dev/null

# 5. Enable UFW (Firewall)
apt install ufw -y
ufw default deny incoming
ufw default allow outgoing
ufw enable

# 6. Disable Root SSH Login
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# 7. Enable Automatic Security Updates
apt install unattended-upgrades -y
dpkg-reconfigure -plow unattended-upgrades

# 8. Log all commands run by users (via bash history)
echo 'export PROMPT_COMMAND="history -a >(tee -a /var/log/bash_history.log)"' >> /etc/profile

# 9. Set Account Lockout Policy
apt install libpam-modules -y
echo "auth required pam_tally2.so onerr=fail deny=5 unlock_time=1800" >> /etc/pam.d/common-auth

echo "[+] Hardening complete. Reboot recommended."
