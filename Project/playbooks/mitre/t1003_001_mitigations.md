---
threat_name: "LSASS Memory"
technique_ids: ["T1003.001"]
severity: Medium
source_doc: "MITRE_ATTACK_Mitigations_T1003.001"
doc_type: mitre
---

> ที่มา: MITRE ATT&CK (T1003.001 — LSASS Memory) ดึงผ่าน mitreattack-python (offline)
> เนื้อหาด้านล่างคือคำอธิบายทางการจาก ATT&CK โดยตรง ไม่ได้เรียบเรียงใหม่
> เพื่อให้อ้างอิงย้อนกลับไปยังเอกสารต้นฉบับได้ตรง

## Phase: containment
### Sub: operating_system_configuration [T1003.001]
**M1028 — Operating System Configuration**

Operating System Configuration involves adjusting system settings and hardening the default configurations of an operating system (OS) to mitigate adversary exploitation and prevent abuse of system functionality. Proper OS configurations address security vulnerabilities, limit attack surfaces, and ensure robust defense against a wide range of techniques. This mitigation can be implemented through the following measures: 

Disable Unused Features:

- Turn off SMBv1, LLMNR, and NetBIOS where not needed.
- Disable remote registry and unnecessary services.

Enforce OS-level Protections:

- Enable Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Control Flow Guard (CFG) on Windows.
- Use AppArmor or SELinux on Linux for mandatory access controls.

Secure Access Settings:

- Enable User Account Control (UAC) for Windows.
- Restrict root/sudo access on Linux/macOS and enforce strong permissions using sudoers files.

File System Hardening:

- Implement least-privilege access for critical files and system directories.
- Audit permissions regularly using tools like icacls (Windows) or getfacl/chmod (Linux/macOS).

Secure Remote Access:

- Restrict RDP, SSH, and VNC to authorized IPs using firewall rules.
- Enable NLA for RDP and enforce strong password/lockout policies.

Harden Boot Configurations:

- Enable Secure Boot and enforce UEFI/BIOS password protection.
- Use BitLocker or LUKS to encrypt boot drives.

Regular Audits:

- Periodically audit OS configurations using tools like CIS Benchmarks or SCAP tools.

*Tools for Implementation*

Windows:

- Microsoft Group Policy Objects (GPO): Centrally enforce OS security settings.
- Windows Defender Exploit Guard: Built-in OS protection against exploits.
- CIS-CAT Pro: Audit Windows security configurations based on CIS Benchmarks.

Linux/macOS:

- AppArmor/SELinux: Enforce mandatory access controls.
- Lynis: Perform comprehensive security audits.
- SCAP Security Guide: Automate configuration hardening using Security Content Automation Protocol.

Cross-Platform:

- Ansible or Chef/Puppet: Automate configuration hardening at scale.
- OpenSCAP: Perform compliance and configuration checks.

### Sub: credential_access_protection [T1003.001]
**M1043 — Credential Access Protection**

Credential Access Protection focuses on implementing measures to prevent adversaries from obtaining credentials, such as passwords, hashes, tokens, or keys, that could be used for unauthorized access. This involves restricting access to credential storage mechanisms, hardening configurations to block credential dumping methods, and using monitoring tools to detect suspicious credential-related activity. This mitigation can be implemented through the following measures:

Restrict Access to Credential Storage:

- Use Case: Prevent adversaries from accessing the SAM (Security Account Manager) database on Windows systems.
- Implementation: Enforce least privilege principles and restrict administrative access to credential stores such as `C:\Windows\System32\config\SAM`.

Use Credential Guard:

- Use Case: Isolate LSASS (Local Security Authority Subsystem Service) memory to prevent credential dumping.
- Implementation: Enable Windows Defender Credential Guard on enterprise endpoints to isolate secrets and protect them from unauthorized access.

Monitor for Credential Dumping Tools:

- Use Case: Detect and block known tools like Mimikatz or Windows Credential Editor.
- Implementation: Flag suspicious process behavior related to credential dumping.

Disable Cached Credentials:

- Use Case: Prevent adversaries from exploiting cached credentials on endpoints.
- Implementation: Configure group policy to reduce or eliminate the use of cached credentials (e.g., set Interactive logon: Number of previous logons to cache to 0).

Enable Secure Boot and Memory Protections:

- Use Case: Prevent memory-based attacks used to extract credentials.
- Implementation: Configure Secure Boot and enforce hardware-based security features like DEP (Data Execution Prevention) and ASLR (Address Space Layout Randomization).

### Sub: privileged_process_integrity [T1003.001]
**M1025 — Privileged Process Integrity**

Privileged Process Integrity focuses on defending highly privileged processes (e.g., system services, antivirus, or authentication processes) from tampering, injection, or compromise by adversaries. These processes often interact with critical components, making them prime targets for techniques like code injection, privilege escalation, and process manipulation. This mitigation can be implemented through the following measures:

Protected Process Mechanisms:

- Enable RunAsPPL on Windows systems to protect LSASS and other critical processes.
- Use registry modifications to enforce protected process settings: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`

Anti-Injection and Memory Protection:

- Enable Control Flow Guard (CFG), DEP, and ASLR to protect against process memory tampering.
- Deploy endpoint protection tools that actively block process injection attempts.

Code Signing Validation:

- Implement policies for Windows Defender Application Control (WDAC) or AppLocker to enforce execution of signed binaries.
- Ensure critical processes are signed with valid certificates.

Access Controls:

- Use DACLs and MIC to limit which users and processes can interact with privileged processes.
- Disable unnecessary debugging capabilities for high-privileged processes.

Kernel-Level Protections:

- Ensure Kernel Patch Protection (PatchGuard) is enabled on Windows systems.
- Leverage SELinux or AppArmor on Linux to enforce kernel-level security policies.

*Tools for Implementation*

Protected Process Light (PPL):

- RunAsPPL (Windows)
- Windows Defender Credential Guard

Code Integrity and Signing:

- Windows Defender Application Control (WDAC)
- AppLocker
- SELinux/AppArmor (Linux)

Memory Protection:

- Control Flow Guard (CFG), Data Execution Prevention (DEP), ASLR

Process Isolation/Sandboxing:

- Firejail (Linux Sandbox)
- Windows Sandbox
- QEMU/KVM-based isolation

Kernel Protection:

- PatchGuard (Windows Kernel Patch Protection)
- SELinux (Mandatory Access Control for Linux)
- AppArmor

### Sub: privileged_account_management [T1003.001]
**M1026 — Privileged Account Management**

Privileged Account Management focuses on implementing policies, controls, and tools to securely manage privileged accounts (e.g., SYSTEM, root, or administrative accounts). This includes restricting access, limiting the scope of permissions, monitoring privileged account usage, and ensuring accountability through logging and auditing.This mitigation can be implemented through the following measures:

Account Permissions and Roles:

- Implement RBAC and least privilege principles to allocate permissions securely.
- Use tools like Active Directory Group Policies to enforce access restrictions.

Credential Security:

- Deploy password vaulting tools like CyberArk, HashiCorp Vault, or KeePass for secure storage and rotation of credentials.
- Enforce password policies for complexity, uniqueness, and expiration using tools like Microsoft Group Policy Objects (GPO).

Multi-Factor Authentication (MFA):

- Enforce MFA for all privileged accounts using Duo Security, Okta, or Microsoft Azure AD MFA.

Privileged Access Management (PAM):

- Use PAM solutions like CyberArk, BeyondTrust, or Thycotic to manage, monitor, and audit privileged access.

Auditing and Monitoring:

- Integrate activity monitoring into your SIEM (e.g., Splunk or QRadar) to detect and alert on anomalous privileged account usage.

Just-In-Time Access:

- Deploy JIT solutions like Azure Privileged Identity Management (PIM) or configure ephemeral roles in AWS and GCP to grant time-limited elevated permissions.

*Tools for Implementation*

Privileged Access Management (PAM):

- CyberArk, BeyondTrust, Thycotic, HashiCorp Vault.

Credential Management:

- Microsoft LAPS (Local Admin Password Solution), Password Safe, HashiCorp Vault, KeePass.

Multi-Factor Authentication:

- Duo Security, Okta, Microsoft Azure MFA, Google Authenticator.

Linux Privilege Management:

- sudo configuration, SELinux, AppArmor.

Just-In-Time Access:

- Azure Privileged Identity Management (PIM), AWS IAM Roles with session constraints, GCP Identity-Aware Proxy.

### Sub: user_training [T1003.001]
**M1017 — User Training**

User Training involves educating employees and contractors on recognizing, reporting, and preventing cyber threats that rely on human interaction, such as phishing, social engineering, and other manipulative techniques. Comprehensive training programs create a human firewall by empowering users to be an active component of the organization's cybersecurity defenses. This mitigation can be implemented through the following measures:

Create Comprehensive Training Programs:

- Design training modules tailored to the organization's risk profile, covering topics such as phishing, password management, and incident reporting.
- Provide role-specific training for high-risk employees, such as helpdesk staff or executives.

Use Simulated Exercises:

- Conduct phishing simulations to measure user susceptibility and provide targeted follow-up training.
- Run social engineering drills to evaluate employee responses and reinforce protocols.

Leverage Gamification and Engagement:

- Introduce interactive learning methods such as quizzes, gamified challenges, and rewards for successful detection and reporting of threats.

Incorporate Security Policies into Onboarding:

- Include cybersecurity training as part of the onboarding process for new employees.
- Provide easy-to-understand materials outlining acceptable use policies and reporting procedures.

Regular Refresher Courses:

- Update training materials to include emerging threats and techniques used by adversaries.
- Ensure all employees complete periodic refresher courses to stay informed.

Emphasize Real-World Scenarios:

- Use case studies of recent attacks to demonstrate the consequences of successful phishing or social engineering.
- Discuss how specific employee actions can prevent or mitigate such attacks.

### Sub: behavior_prevention_on_endpoint [T1003.001]
**M1040 — Behavior Prevention on Endpoint**

Behavior Prevention on Endpoint refers to the use of technologies and strategies to detect and block potentially malicious activities by analyzing the behavior of processes, files, API calls, and other endpoint events. Rather than relying solely on known signatures, this approach leverages heuristics, machine learning, and real-time monitoring to identify anomalous patterns indicative of an attack. This mitigation can be implemented through the following measures:

Suspicious Process Behavior:

- Implementation: Use Endpoint Detection and Response (EDR) tools to monitor and block processes exhibiting unusual behavior, such as privilege escalation attempts.
- Use Case: An attacker uses a known vulnerability to spawn a privileged process from a user-level application. The endpoint tool detects the abnormal parent-child process relationship and blocks the action.

Unauthorized File Access:

- Implementation: Leverage Data Loss Prevention (DLP) or endpoint tools to block processes attempting to access sensitive files without proper authorization.
- Use Case: A process tries to read or modify a sensitive file located in a restricted directory, such as /etc/shadow on Linux or the SAM registry hive on Windows. The endpoint tool identifies this anomalous behavior and prevents it.

Abnormal API Calls:

- Implementation: Implement runtime analysis tools to monitor API calls and block those associated with malicious activities.
- Use Case: A process dynamically injects itself into another process to hijack its execution. The endpoint detects the abnormal use of APIs like `OpenProcess` and `WriteProcessMemory` and terminates the offending process.

Exploit Prevention:

- Implementation: Use behavioral exploit prevention tools to detect and block exploits attempting to gain unauthorized access.
- Use Case: A buffer overflow exploit is launched against a vulnerable application. The endpoint detects the anomalous memory write operation and halts the process.

### Sub: password_policies [T1003.001]
**M1027 — Password Policies**

Set and enforce secure password policies for accounts to reduce the likelihood of unauthorized access. Strong password policies include enforcing password complexity, requiring regular password changes, and preventing password reuse. This mitigation can be implemented through the following measures:

Windows Systems:

- Use Group Policy Management Console (GPMC) to configure:
    - Minimum password length (e.g., 12+ characters).
    - Password complexity requirements.
    - Password history (e.g., disallow last 24 passwords).
    - Account lockout duration and thresholds.

Linux Systems:

- Configure Pluggable Authentication Modules (PAM):
- Use `pam_pwquality` to enforce complexity and length requirements.
- Implement `pam_tally2` or `pam_faillock` for account lockouts.
- Use `pwunconv` to disable password reuse.

Password Managers:

- Enforce usage of enterprise password managers (e.g., Bitwarden, 1Password, LastPass) to generate and store strong passwords.

Password Blacklisting:

- Use tools like Have I Been Pwned password checks or NIST-based blacklist solutions to prevent users from setting compromised passwords.

Regular Auditing:

- Periodically audit password policies and account configurations to ensure compliance using tools like LAPS (Local Admin Password Solution) and vulnerability scanners.

*Tools for Implementation*

Windows:

- Group Policy Management Console (GPMC): Enforce password policies.
- Microsoft Local Administrator Password Solution (LAPS): Enforce random, unique admin passwords.

Linux/macOS:

- PAM Modules (pam_pwquality, pam_tally2, pam_faillock): Enforce password rules.
- Lynis: Audit password policies and system configurations.

Cross-Platform:

- Password Managers (Bitwarden, 1Password, KeePass): Manage and enforce strong passwords.
- Have I Been Pwned API: Prevent the use of breached passwords.
- NIST SP 800-63B compliant tools: Enforce password guidelines and blacklisting.

## Phase: eradication
### Sub: operating_system_configuration [T1003.001]
**M1028 — Operating System Configuration**

Operating System Configuration involves adjusting system settings and hardening the default configurations of an operating system (OS) to mitigate adversary exploitation and prevent abuse of system functionality. Proper OS configurations address security vulnerabilities, limit attack surfaces, and ensure robust defense against a wide range of techniques. This mitigation can be implemented through the following measures: 

Disable Unused Features:

- Turn off SMBv1, LLMNR, and NetBIOS where not needed.
- Disable remote registry and unnecessary services.

Enforce OS-level Protections:

- Enable Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Control Flow Guard (CFG) on Windows.
- Use AppArmor or SELinux on Linux for mandatory access controls.

Secure Access Settings:

- Enable User Account Control (UAC) for Windows.
- Restrict root/sudo access on Linux/macOS and enforce strong permissions using sudoers files.

File System Hardening:

- Implement least-privilege access for critical files and system directories.
- Audit permissions regularly using tools like icacls (Windows) or getfacl/chmod (Linux/macOS).

Secure Remote Access:

- Restrict RDP, SSH, and VNC to authorized IPs using firewall rules.
- Enable NLA for RDP and enforce strong password/lockout policies.

Harden Boot Configurations:

- Enable Secure Boot and enforce UEFI/BIOS password protection.
- Use BitLocker or LUKS to encrypt boot drives.

Regular Audits:

- Periodically audit OS configurations using tools like CIS Benchmarks or SCAP tools.

*Tools for Implementation*

Windows:

- Microsoft Group Policy Objects (GPO): Centrally enforce OS security settings.
- Windows Defender Exploit Guard: Built-in OS protection against exploits.
- CIS-CAT Pro: Audit Windows security configurations based on CIS Benchmarks.

Linux/macOS:

- AppArmor/SELinux: Enforce mandatory access controls.
- Lynis: Perform comprehensive security audits.
- SCAP Security Guide: Automate configuration hardening using Security Content Automation Protocol.

Cross-Platform:

- Ansible or Chef/Puppet: Automate configuration hardening at scale.
- OpenSCAP: Perform compliance and configuration checks.

### Sub: credential_access_protection [T1003.001]
**M1043 — Credential Access Protection**

Credential Access Protection focuses on implementing measures to prevent adversaries from obtaining credentials, such as passwords, hashes, tokens, or keys, that could be used for unauthorized access. This involves restricting access to credential storage mechanisms, hardening configurations to block credential dumping methods, and using monitoring tools to detect suspicious credential-related activity. This mitigation can be implemented through the following measures:

Restrict Access to Credential Storage:

- Use Case: Prevent adversaries from accessing the SAM (Security Account Manager) database on Windows systems.
- Implementation: Enforce least privilege principles and restrict administrative access to credential stores such as `C:\Windows\System32\config\SAM`.

Use Credential Guard:

- Use Case: Isolate LSASS (Local Security Authority Subsystem Service) memory to prevent credential dumping.
- Implementation: Enable Windows Defender Credential Guard on enterprise endpoints to isolate secrets and protect them from unauthorized access.

Monitor for Credential Dumping Tools:

- Use Case: Detect and block known tools like Mimikatz or Windows Credential Editor.
- Implementation: Flag suspicious process behavior related to credential dumping.

Disable Cached Credentials:

- Use Case: Prevent adversaries from exploiting cached credentials on endpoints.
- Implementation: Configure group policy to reduce or eliminate the use of cached credentials (e.g., set Interactive logon: Number of previous logons to cache to 0).

Enable Secure Boot and Memory Protections:

- Use Case: Prevent memory-based attacks used to extract credentials.
- Implementation: Configure Secure Boot and enforce hardware-based security features like DEP (Data Execution Prevention) and ASLR (Address Space Layout Randomization).

### Sub: privileged_process_integrity [T1003.001]
**M1025 — Privileged Process Integrity**

Privileged Process Integrity focuses on defending highly privileged processes (e.g., system services, antivirus, or authentication processes) from tampering, injection, or compromise by adversaries. These processes often interact with critical components, making them prime targets for techniques like code injection, privilege escalation, and process manipulation. This mitigation can be implemented through the following measures:

Protected Process Mechanisms:

- Enable RunAsPPL on Windows systems to protect LSASS and other critical processes.
- Use registry modifications to enforce protected process settings: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`

Anti-Injection and Memory Protection:

- Enable Control Flow Guard (CFG), DEP, and ASLR to protect against process memory tampering.
- Deploy endpoint protection tools that actively block process injection attempts.

Code Signing Validation:

- Implement policies for Windows Defender Application Control (WDAC) or AppLocker to enforce execution of signed binaries.
- Ensure critical processes are signed with valid certificates.

Access Controls:

- Use DACLs and MIC to limit which users and processes can interact with privileged processes.
- Disable unnecessary debugging capabilities for high-privileged processes.

Kernel-Level Protections:

- Ensure Kernel Patch Protection (PatchGuard) is enabled on Windows systems.
- Leverage SELinux or AppArmor on Linux to enforce kernel-level security policies.

*Tools for Implementation*

Protected Process Light (PPL):

- RunAsPPL (Windows)
- Windows Defender Credential Guard

Code Integrity and Signing:

- Windows Defender Application Control (WDAC)
- AppLocker
- SELinux/AppArmor (Linux)

Memory Protection:

- Control Flow Guard (CFG), Data Execution Prevention (DEP), ASLR

Process Isolation/Sandboxing:

- Firejail (Linux Sandbox)
- Windows Sandbox
- QEMU/KVM-based isolation

Kernel Protection:

- PatchGuard (Windows Kernel Patch Protection)
- SELinux (Mandatory Access Control for Linux)
- AppArmor

### Sub: privileged_account_management [T1003.001]
**M1026 — Privileged Account Management**

Privileged Account Management focuses on implementing policies, controls, and tools to securely manage privileged accounts (e.g., SYSTEM, root, or administrative accounts). This includes restricting access, limiting the scope of permissions, monitoring privileged account usage, and ensuring accountability through logging and auditing.This mitigation can be implemented through the following measures:

Account Permissions and Roles:

- Implement RBAC and least privilege principles to allocate permissions securely.
- Use tools like Active Directory Group Policies to enforce access restrictions.

Credential Security:

- Deploy password vaulting tools like CyberArk, HashiCorp Vault, or KeePass for secure storage and rotation of credentials.
- Enforce password policies for complexity, uniqueness, and expiration using tools like Microsoft Group Policy Objects (GPO).

Multi-Factor Authentication (MFA):

- Enforce MFA for all privileged accounts using Duo Security, Okta, or Microsoft Azure AD MFA.

Privileged Access Management (PAM):

- Use PAM solutions like CyberArk, BeyondTrust, or Thycotic to manage, monitor, and audit privileged access.

Auditing and Monitoring:

- Integrate activity monitoring into your SIEM (e.g., Splunk or QRadar) to detect and alert on anomalous privileged account usage.

Just-In-Time Access:

- Deploy JIT solutions like Azure Privileged Identity Management (PIM) or configure ephemeral roles in AWS and GCP to grant time-limited elevated permissions.

*Tools for Implementation*

Privileged Access Management (PAM):

- CyberArk, BeyondTrust, Thycotic, HashiCorp Vault.

Credential Management:

- Microsoft LAPS (Local Admin Password Solution), Password Safe, HashiCorp Vault, KeePass.

Multi-Factor Authentication:

- Duo Security, Okta, Microsoft Azure MFA, Google Authenticator.

Linux Privilege Management:

- sudo configuration, SELinux, AppArmor.

Just-In-Time Access:

- Azure Privileged Identity Management (PIM), AWS IAM Roles with session constraints, GCP Identity-Aware Proxy.

### Sub: user_training [T1003.001]
**M1017 — User Training**

User Training involves educating employees and contractors on recognizing, reporting, and preventing cyber threats that rely on human interaction, such as phishing, social engineering, and other manipulative techniques. Comprehensive training programs create a human firewall by empowering users to be an active component of the organization's cybersecurity defenses. This mitigation can be implemented through the following measures:

Create Comprehensive Training Programs:

- Design training modules tailored to the organization's risk profile, covering topics such as phishing, password management, and incident reporting.
- Provide role-specific training for high-risk employees, such as helpdesk staff or executives.

Use Simulated Exercises:

- Conduct phishing simulations to measure user susceptibility and provide targeted follow-up training.
- Run social engineering drills to evaluate employee responses and reinforce protocols.

Leverage Gamification and Engagement:

- Introduce interactive learning methods such as quizzes, gamified challenges, and rewards for successful detection and reporting of threats.

Incorporate Security Policies into Onboarding:

- Include cybersecurity training as part of the onboarding process for new employees.
- Provide easy-to-understand materials outlining acceptable use policies and reporting procedures.

Regular Refresher Courses:

- Update training materials to include emerging threats and techniques used by adversaries.
- Ensure all employees complete periodic refresher courses to stay informed.

Emphasize Real-World Scenarios:

- Use case studies of recent attacks to demonstrate the consequences of successful phishing or social engineering.
- Discuss how specific employee actions can prevent or mitigate such attacks.

### Sub: behavior_prevention_on_endpoint [T1003.001]
**M1040 — Behavior Prevention on Endpoint**

Behavior Prevention on Endpoint refers to the use of technologies and strategies to detect and block potentially malicious activities by analyzing the behavior of processes, files, API calls, and other endpoint events. Rather than relying solely on known signatures, this approach leverages heuristics, machine learning, and real-time monitoring to identify anomalous patterns indicative of an attack. This mitigation can be implemented through the following measures:

Suspicious Process Behavior:

- Implementation: Use Endpoint Detection and Response (EDR) tools to monitor and block processes exhibiting unusual behavior, such as privilege escalation attempts.
- Use Case: An attacker uses a known vulnerability to spawn a privileged process from a user-level application. The endpoint tool detects the abnormal parent-child process relationship and blocks the action.

Unauthorized File Access:

- Implementation: Leverage Data Loss Prevention (DLP) or endpoint tools to block processes attempting to access sensitive files without proper authorization.
- Use Case: A process tries to read or modify a sensitive file located in a restricted directory, such as /etc/shadow on Linux or the SAM registry hive on Windows. The endpoint tool identifies this anomalous behavior and prevents it.

Abnormal API Calls:

- Implementation: Implement runtime analysis tools to monitor API calls and block those associated with malicious activities.
- Use Case: A process dynamically injects itself into another process to hijack its execution. The endpoint detects the abnormal use of APIs like `OpenProcess` and `WriteProcessMemory` and terminates the offending process.

Exploit Prevention:

- Implementation: Use behavioral exploit prevention tools to detect and block exploits attempting to gain unauthorized access.
- Use Case: A buffer overflow exploit is launched against a vulnerable application. The endpoint detects the anomalous memory write operation and halts the process.

### Sub: password_policies [T1003.001]
**M1027 — Password Policies**

Set and enforce secure password policies for accounts to reduce the likelihood of unauthorized access. Strong password policies include enforcing password complexity, requiring regular password changes, and preventing password reuse. This mitigation can be implemented through the following measures:

Windows Systems:

- Use Group Policy Management Console (GPMC) to configure:
    - Minimum password length (e.g., 12+ characters).
    - Password complexity requirements.
    - Password history (e.g., disallow last 24 passwords).
    - Account lockout duration and thresholds.

Linux Systems:

- Configure Pluggable Authentication Modules (PAM):
- Use `pam_pwquality` to enforce complexity and length requirements.
- Implement `pam_tally2` or `pam_faillock` for account lockouts.
- Use `pwunconv` to disable password reuse.

Password Managers:

- Enforce usage of enterprise password managers (e.g., Bitwarden, 1Password, LastPass) to generate and store strong passwords.

Password Blacklisting:

- Use tools like Have I Been Pwned password checks or NIST-based blacklist solutions to prevent users from setting compromised passwords.

Regular Auditing:

- Periodically audit password policies and account configurations to ensure compliance using tools like LAPS (Local Admin Password Solution) and vulnerability scanners.

*Tools for Implementation*

Windows:

- Group Policy Management Console (GPMC): Enforce password policies.
- Microsoft Local Administrator Password Solution (LAPS): Enforce random, unique admin passwords.

Linux/macOS:

- PAM Modules (pam_pwquality, pam_tally2, pam_faillock): Enforce password rules.
- Lynis: Audit password policies and system configurations.

Cross-Platform:

- Password Managers (Bitwarden, 1Password, KeePass): Manage and enforce strong passwords.
- Have I Been Pwned API: Prevent the use of breached passwords.
- NIST SP 800-63B compliant tools: Enforce password guidelines and blacklisting.

## Phase: recovery
### Sub: operating_system_configuration [T1003.001]
**M1028 — Operating System Configuration**

Operating System Configuration involves adjusting system settings and hardening the default configurations of an operating system (OS) to mitigate adversary exploitation and prevent abuse of system functionality. Proper OS configurations address security vulnerabilities, limit attack surfaces, and ensure robust defense against a wide range of techniques. This mitigation can be implemented through the following measures: 

Disable Unused Features:

- Turn off SMBv1, LLMNR, and NetBIOS where not needed.
- Disable remote registry and unnecessary services.

Enforce OS-level Protections:

- Enable Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Control Flow Guard (CFG) on Windows.
- Use AppArmor or SELinux on Linux for mandatory access controls.

Secure Access Settings:

- Enable User Account Control (UAC) for Windows.
- Restrict root/sudo access on Linux/macOS and enforce strong permissions using sudoers files.

File System Hardening:

- Implement least-privilege access for critical files and system directories.
- Audit permissions regularly using tools like icacls (Windows) or getfacl/chmod (Linux/macOS).

Secure Remote Access:

- Restrict RDP, SSH, and VNC to authorized IPs using firewall rules.
- Enable NLA for RDP and enforce strong password/lockout policies.

Harden Boot Configurations:

- Enable Secure Boot and enforce UEFI/BIOS password protection.
- Use BitLocker or LUKS to encrypt boot drives.

Regular Audits:

- Periodically audit OS configurations using tools like CIS Benchmarks or SCAP tools.

*Tools for Implementation*

Windows:

- Microsoft Group Policy Objects (GPO): Centrally enforce OS security settings.
- Windows Defender Exploit Guard: Built-in OS protection against exploits.
- CIS-CAT Pro: Audit Windows security configurations based on CIS Benchmarks.

Linux/macOS:

- AppArmor/SELinux: Enforce mandatory access controls.
- Lynis: Perform comprehensive security audits.
- SCAP Security Guide: Automate configuration hardening using Security Content Automation Protocol.

Cross-Platform:

- Ansible or Chef/Puppet: Automate configuration hardening at scale.
- OpenSCAP: Perform compliance and configuration checks.

### Sub: credential_access_protection [T1003.001]
**M1043 — Credential Access Protection**

Credential Access Protection focuses on implementing measures to prevent adversaries from obtaining credentials, such as passwords, hashes, tokens, or keys, that could be used for unauthorized access. This involves restricting access to credential storage mechanisms, hardening configurations to block credential dumping methods, and using monitoring tools to detect suspicious credential-related activity. This mitigation can be implemented through the following measures:

Restrict Access to Credential Storage:

- Use Case: Prevent adversaries from accessing the SAM (Security Account Manager) database on Windows systems.
- Implementation: Enforce least privilege principles and restrict administrative access to credential stores such as `C:\Windows\System32\config\SAM`.

Use Credential Guard:

- Use Case: Isolate LSASS (Local Security Authority Subsystem Service) memory to prevent credential dumping.
- Implementation: Enable Windows Defender Credential Guard on enterprise endpoints to isolate secrets and protect them from unauthorized access.

Monitor for Credential Dumping Tools:

- Use Case: Detect and block known tools like Mimikatz or Windows Credential Editor.
- Implementation: Flag suspicious process behavior related to credential dumping.

Disable Cached Credentials:

- Use Case: Prevent adversaries from exploiting cached credentials on endpoints.
- Implementation: Configure group policy to reduce or eliminate the use of cached credentials (e.g., set Interactive logon: Number of previous logons to cache to 0).

Enable Secure Boot and Memory Protections:

- Use Case: Prevent memory-based attacks used to extract credentials.
- Implementation: Configure Secure Boot and enforce hardware-based security features like DEP (Data Execution Prevention) and ASLR (Address Space Layout Randomization).

### Sub: privileged_process_integrity [T1003.001]
**M1025 — Privileged Process Integrity**

Privileged Process Integrity focuses on defending highly privileged processes (e.g., system services, antivirus, or authentication processes) from tampering, injection, or compromise by adversaries. These processes often interact with critical components, making them prime targets for techniques like code injection, privilege escalation, and process manipulation. This mitigation can be implemented through the following measures:

Protected Process Mechanisms:

- Enable RunAsPPL on Windows systems to protect LSASS and other critical processes.
- Use registry modifications to enforce protected process settings: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`

Anti-Injection and Memory Protection:

- Enable Control Flow Guard (CFG), DEP, and ASLR to protect against process memory tampering.
- Deploy endpoint protection tools that actively block process injection attempts.

Code Signing Validation:

- Implement policies for Windows Defender Application Control (WDAC) or AppLocker to enforce execution of signed binaries.
- Ensure critical processes are signed with valid certificates.

Access Controls:

- Use DACLs and MIC to limit which users and processes can interact with privileged processes.
- Disable unnecessary debugging capabilities for high-privileged processes.

Kernel-Level Protections:

- Ensure Kernel Patch Protection (PatchGuard) is enabled on Windows systems.
- Leverage SELinux or AppArmor on Linux to enforce kernel-level security policies.

*Tools for Implementation*

Protected Process Light (PPL):

- RunAsPPL (Windows)
- Windows Defender Credential Guard

Code Integrity and Signing:

- Windows Defender Application Control (WDAC)
- AppLocker
- SELinux/AppArmor (Linux)

Memory Protection:

- Control Flow Guard (CFG), Data Execution Prevention (DEP), ASLR

Process Isolation/Sandboxing:

- Firejail (Linux Sandbox)
- Windows Sandbox
- QEMU/KVM-based isolation

Kernel Protection:

- PatchGuard (Windows Kernel Patch Protection)
- SELinux (Mandatory Access Control for Linux)
- AppArmor

### Sub: privileged_account_management [T1003.001]
**M1026 — Privileged Account Management**

Privileged Account Management focuses on implementing policies, controls, and tools to securely manage privileged accounts (e.g., SYSTEM, root, or administrative accounts). This includes restricting access, limiting the scope of permissions, monitoring privileged account usage, and ensuring accountability through logging and auditing.This mitigation can be implemented through the following measures:

Account Permissions and Roles:

- Implement RBAC and least privilege principles to allocate permissions securely.
- Use tools like Active Directory Group Policies to enforce access restrictions.

Credential Security:

- Deploy password vaulting tools like CyberArk, HashiCorp Vault, or KeePass for secure storage and rotation of credentials.
- Enforce password policies for complexity, uniqueness, and expiration using tools like Microsoft Group Policy Objects (GPO).

Multi-Factor Authentication (MFA):

- Enforce MFA for all privileged accounts using Duo Security, Okta, or Microsoft Azure AD MFA.

Privileged Access Management (PAM):

- Use PAM solutions like CyberArk, BeyondTrust, or Thycotic to manage, monitor, and audit privileged access.

Auditing and Monitoring:

- Integrate activity monitoring into your SIEM (e.g., Splunk or QRadar) to detect and alert on anomalous privileged account usage.

Just-In-Time Access:

- Deploy JIT solutions like Azure Privileged Identity Management (PIM) or configure ephemeral roles in AWS and GCP to grant time-limited elevated permissions.

*Tools for Implementation*

Privileged Access Management (PAM):

- CyberArk, BeyondTrust, Thycotic, HashiCorp Vault.

Credential Management:

- Microsoft LAPS (Local Admin Password Solution), Password Safe, HashiCorp Vault, KeePass.

Multi-Factor Authentication:

- Duo Security, Okta, Microsoft Azure MFA, Google Authenticator.

Linux Privilege Management:

- sudo configuration, SELinux, AppArmor.

Just-In-Time Access:

- Azure Privileged Identity Management (PIM), AWS IAM Roles with session constraints, GCP Identity-Aware Proxy.

### Sub: user_training [T1003.001]
**M1017 — User Training**

User Training involves educating employees and contractors on recognizing, reporting, and preventing cyber threats that rely on human interaction, such as phishing, social engineering, and other manipulative techniques. Comprehensive training programs create a human firewall by empowering users to be an active component of the organization's cybersecurity defenses. This mitigation can be implemented through the following measures:

Create Comprehensive Training Programs:

- Design training modules tailored to the organization's risk profile, covering topics such as phishing, password management, and incident reporting.
- Provide role-specific training for high-risk employees, such as helpdesk staff or executives.

Use Simulated Exercises:

- Conduct phishing simulations to measure user susceptibility and provide targeted follow-up training.
- Run social engineering drills to evaluate employee responses and reinforce protocols.

Leverage Gamification and Engagement:

- Introduce interactive learning methods such as quizzes, gamified challenges, and rewards for successful detection and reporting of threats.

Incorporate Security Policies into Onboarding:

- Include cybersecurity training as part of the onboarding process for new employees.
- Provide easy-to-understand materials outlining acceptable use policies and reporting procedures.

Regular Refresher Courses:

- Update training materials to include emerging threats and techniques used by adversaries.
- Ensure all employees complete periodic refresher courses to stay informed.

Emphasize Real-World Scenarios:

- Use case studies of recent attacks to demonstrate the consequences of successful phishing or social engineering.
- Discuss how specific employee actions can prevent or mitigate such attacks.

### Sub: behavior_prevention_on_endpoint [T1003.001]
**M1040 — Behavior Prevention on Endpoint**

Behavior Prevention on Endpoint refers to the use of technologies and strategies to detect and block potentially malicious activities by analyzing the behavior of processes, files, API calls, and other endpoint events. Rather than relying solely on known signatures, this approach leverages heuristics, machine learning, and real-time monitoring to identify anomalous patterns indicative of an attack. This mitigation can be implemented through the following measures:

Suspicious Process Behavior:

- Implementation: Use Endpoint Detection and Response (EDR) tools to monitor and block processes exhibiting unusual behavior, such as privilege escalation attempts.
- Use Case: An attacker uses a known vulnerability to spawn a privileged process from a user-level application. The endpoint tool detects the abnormal parent-child process relationship and blocks the action.

Unauthorized File Access:

- Implementation: Leverage Data Loss Prevention (DLP) or endpoint tools to block processes attempting to access sensitive files without proper authorization.
- Use Case: A process tries to read or modify a sensitive file located in a restricted directory, such as /etc/shadow on Linux or the SAM registry hive on Windows. The endpoint tool identifies this anomalous behavior and prevents it.

Abnormal API Calls:

- Implementation: Implement runtime analysis tools to monitor API calls and block those associated with malicious activities.
- Use Case: A process dynamically injects itself into another process to hijack its execution. The endpoint detects the abnormal use of APIs like `OpenProcess` and `WriteProcessMemory` and terminates the offending process.

Exploit Prevention:

- Implementation: Use behavioral exploit prevention tools to detect and block exploits attempting to gain unauthorized access.
- Use Case: A buffer overflow exploit is launched against a vulnerable application. The endpoint detects the anomalous memory write operation and halts the process.

### Sub: password_policies [T1003.001]
**M1027 — Password Policies**

Set and enforce secure password policies for accounts to reduce the likelihood of unauthorized access. Strong password policies include enforcing password complexity, requiring regular password changes, and preventing password reuse. This mitigation can be implemented through the following measures:

Windows Systems:

- Use Group Policy Management Console (GPMC) to configure:
    - Minimum password length (e.g., 12+ characters).
    - Password complexity requirements.
    - Password history (e.g., disallow last 24 passwords).
    - Account lockout duration and thresholds.

Linux Systems:

- Configure Pluggable Authentication Modules (PAM):
- Use `pam_pwquality` to enforce complexity and length requirements.
- Implement `pam_tally2` or `pam_faillock` for account lockouts.
- Use `pwunconv` to disable password reuse.

Password Managers:

- Enforce usage of enterprise password managers (e.g., Bitwarden, 1Password, LastPass) to generate and store strong passwords.

Password Blacklisting:

- Use tools like Have I Been Pwned password checks or NIST-based blacklist solutions to prevent users from setting compromised passwords.

Regular Auditing:

- Periodically audit password policies and account configurations to ensure compliance using tools like LAPS (Local Admin Password Solution) and vulnerability scanners.

*Tools for Implementation*

Windows:

- Group Policy Management Console (GPMC): Enforce password policies.
- Microsoft Local Administrator Password Solution (LAPS): Enforce random, unique admin passwords.

Linux/macOS:

- PAM Modules (pam_pwquality, pam_tally2, pam_faillock): Enforce password rules.
- Lynis: Audit password policies and system configurations.

Cross-Platform:

- Password Managers (Bitwarden, 1Password, KeePass): Manage and enforce strong passwords.
- Have I Been Pwned API: Prevent the use of breached passwords.
- NIST SP 800-63B compliant tools: Enforce password guidelines and blacklisting.
