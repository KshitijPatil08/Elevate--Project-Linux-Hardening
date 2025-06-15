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

## Run the audit script:

sudo python3 audit.py

Follow the prompts to view the audit report and optionally apply hardening changes.

## Requirements

- Python 3.x
- ufw (Uncomplicated Firewall)   
- chkrootkit (for rootkit detection)  
- Linux system with systemctl (systemd)

## Notes
- The script requires sudo privileges to perform some checks and apply changes.
- It dynamically detects running services and disables unused insecure services during hardening.
- After applying hardening, a system reboot is recommended.

## Contributing
Contributions and suggestions are welcome! Please open an issue or submit a pull request.

## Known Issue: Login Failure After Hardening
Problem:
After running the Linux hardening script, you may get locked out of the system even with the correct password.

## Symptom:
- Login fails with correct password, even though it worked earlier. This is due to the following line added to /etc/pam.d/common-auth auth required pam_tally2.so onerr=fail deny=5 unlock_time=1800

## Cause:
The module pam_tally2.so may not be installed on all systems. With onerr=fail, PAM denies login if the module is missing.

## Fix:

Boot into recovery mode.
- Step 1: Press E once the timer starts of the system to load the linux
- Step 2: Go to the bottom there will be the line 15 or 14 with last know written like ro quiet splash instead of this write rw init=/bin/bash and press enter then press ctrl+x
- Step 3: The recovery mode will get on there the type **nano /etc/pam.d/common-auth** there then the file will get open
- Step 4: Edit the file:Comment out or remove this line: **auth required pam_tally2.so onerr=fail deny=5 unlock_time=1800** or you can remove this line.
- Step 5: After remove or comment the line press **ctrl+o** hit **enter** to save the file then press **ctrl+x** to exit.
- Step 6: To start the OS Enter the command **rebbot -f** if you type only reboot it will show the error becuase we are in recovery mode if we are in systemctl state then we can run this command.

## System starts
- Then the OS start normally and then you can enter into the system

