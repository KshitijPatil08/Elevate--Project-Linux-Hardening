import os
import subprocess
from datetime import datetime

def check_firewall():
    try:
        output = subprocess.getoutput("sudo ufw status")
        return "active" in output.lower(), output
    except:
        return False, "Failed to check UFW"

def check_ssh_config():
    try:
        with open("/etc/ssh/sshd_config", "r") as file:
            config = file.read().lower()
        issues = []
        if "permitrootlogin yes" in config:
            issues.append("PermitRootLogin is enabled")
        if "passwordauthentication yes" in config:
            issues.append("PasswordAuthentication is enabled")
        return issues if issues else ["Secure SSH settings"]
    except:
        return ["Failed to read SSH config"]

def check_file_permissions():
    issues = []
    try:
        shadow_perm = oct(os.stat('/etc/shadow').st_mode)[-3:]
        passwd_perm = oct(os.stat('/etc/passwd').st_mode)[-3:]
        if shadow_perm != "600":
            issues.append(f"/etc/shadow permission is {shadow_perm}, should be 600")
        if passwd_perm not in ["644", "640"]:
            issues.append(f"/etc/passwd permission is {passwd_perm}, should be 644 or 640")
    except:
        issues.append("Failed to check file permissions")
    return issues if issues else ["Key file permissions are secure"]

def check_services():
    try:
        output = subprocess.getoutput("systemctl list-units --type=service --state=running")
        suspicious = []
        for line in output.splitlines():
            if any(service in line for service in ["telnet", "ftp", "rsh", "nfs"]):
                suspicious.append(f"Suspicious service running: {line}")
        return suspicious if suspicious else ["No suspicious services running"]
    except:
        return ["Failed to check running services"]

def check_rootkits():
    try:
        output = subprocess.getoutput("sudo chkrootkit")
        if "INFECTED" in output or "suspicious" in output.lower():
            return ["Potential rootkit detected:\n" + output]
        else:
            return ["No rootkits detected"]
    except:
        return ["chkrootkit not installed or failed to run"]

def generate_report(results, score):
    report_path = "audit_report.txt"
    with open(report_path, "w") as f:
        f.write("=== Linux Hardening Audit Report ===\n")
        f.write(f"Generated on: {datetime.now()}\n\n")
        for section, content in results.items():
            f.write(f"--- {section} ---\n")
            for line in content:
                f.write(f"- {line}\n")
            f.write("\n")
        f.write(f"Security Score: {score}/5\n")
        if score == 5:
            f.write("System is well hardened.\n")
        else:
            f.write("Recommendations:\n")
            if score < 5: f.write("- Improve firewall/SSH settings\n")
            if score < 4: f.write("- Harden file permissions or disable insecure services\n")
    print(f"[+] Report generated at: {report_path}")

def apply_hardening():
    bash_script = """#!/bin/bash
echo "Starting Linux Hardening Script..."

# 1. Update System Packages
apt update && apt upgrade -y

# 2. Disable Unused Services
systemctl disable bluetooth.service
systemctl disable cups.service
systemctl disable avahi-daemon.service

# 3. Enforce Password Policy
sed -i '/^PASS_MAX_DAYS/ c\\PASS_MAX_DAYS   90' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/ c\\PASS_MIN_DAYS   10' /etc/login.defs
sed -i '/^PASS_WARN_AGE/ c\\PASS_WARN_AGE   7' /etc/login.defs

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
"""

    script_path = "apply_hardening.sh"
    with open(script_path, "w") as file:
        file.write(bash_script)

    subprocess.run(["chmod", "+x", script_path])
    print("\n[*] Running hardening script (requires sudo)...\n")
    subprocess.run(["sudo", "./" + script_path])

def main():
    print("[*] Starting Linux hardening audit...\n")
    results = {}

    fw_active, fw_output = check_firewall()
    results["Firewall Status"] = [fw_output]

    ssh_issues = check_ssh_config()
    results["SSH Configuration"] = ssh_issues

    perm_issues = check_file_permissions()
    results["File Permissions"] = perm_issues

    svc_issues = check_services()
    results["Running Services"] = svc_issues

    rk_issues = check_rootkits()
    results["Rootkit Check"] = rk_issues

    score = 5
    if not fw_active: score -= 1
    if any("permitrootlogin" in x.lower() or "passwordauthentication" in x.lower() for x in ssh_issues): score -= 1
    if any("permission" in x.lower() for x in perm_issues): score -= 1
    if any("suspicious" in x.lower() for x in svc_issues): score -= 1
    if any("infected" in x.lower() for x in rk_issues): score -= 1

    generate_report(results, score)

    choice = input("Would you like to automatically apply hardening changes? (yes/no): ").strip().lower()
    if choice == "yes":
        apply_hardening()
    else:
        print("[-] No changes applied.")

if __name__ == "__main__":
    main()

