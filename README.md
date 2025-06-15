# Elevate--Project-Linux-Hardening

Elevate is a Python-based Linux hardening audit tool that checks the security posture of your Linux system by performing various checks and optionally applies automated hardening changes to improve system security.

## Features

- Firewall Status Check: Verifies if UFW (Uncomplicated Firewall) is active.
- SSH Configuration Audit: Detects insecure SSH settings such as `PermitRootLogin` and `PasswordAuthentication`.
- File Permission Checks: Ensures critical system files like `/etc/shadow` and `/etc/passwd` have secure permissions.
- Running Services Audit: Detects suspicious or unnecessary running services that could be potential security risks.
- Rootkit Detection: Runs `chkrootkit` to check for rootkits and malware.
- Automated Hardening: Offers to apply security hardening changes via a bash script, including:
  - System updates and upgrades
  - Disabling unused services dynamically based on running services
  - Enforcing password policies
  - Setting proper file permissions
  - Enabling and configuring UFW firewall
  - Disabling root SSH login
  - Enabling automatic security updates
  - Account lockout policy to prevent brute force attacks
  - Logging user commands for auditing

## Usage

1. Clone the repository:

   ```bash
   git clone https://github.com/KshitijPatil08/Elevate--Project-Linux-Hardening.git
   cd Elevate--Project-Linux-Hardening
Run the audit script:

sudo python3 audit.py

Follow the prompts to view the audit report and optionally apply hardening changes.

Requirements

Python 3.x
ufw (Uncomplicated Firewall)

chkrootkit (for rootkit detection)

Linux system with systemctl (systemd)

Notes
The script requires sudo privileges to perform some checks and apply changes.

It dynamically detects running services and disables unused insecure services during hardening.

After applying hardening, a system reboot is recommended.

Contributing
Contributions and suggestions are welcome! Please open an issue or submit a pull request.
