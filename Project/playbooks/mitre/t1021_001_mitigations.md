---
threat_name: "Remote Desktop Protocol"
technique_ids: ["T1021.001"]
severity: Medium
source_doc: "MITRE_ATTACK_Mitigations_T1021.001"
doc_type: mitre
---

> ที่มา: MITRE ATT&CK (T1021.001 — Remote Desktop Protocol) ดึงผ่าน mitreattack-python (offline)
> เนื้อหาด้านล่างคือคำอธิบายทางการจาก ATT&CK โดยตรง ไม่ได้เรียบเรียงใหม่
> เพื่อให้อ้างอิงย้อนกลับไปยังเอกสารต้นฉบับได้ตรง

## Phase: containment
### Sub: audit [T1021.001]
**M1047 — Audit**

Auditing is the process of recording activity and systematically reviewing and analyzing the activity and system configurations. The primary purpose of auditing is to detect anomalies and identify potential threats or weaknesses in the environment. Proper auditing configurations can also help to meet compliance requirements. The process of auditing encompasses regular analysis of user behaviors and system logs in support of proactive security measures.

Auditing is applicable to all systems used within an organization, from the front door of a building to accessing a file on a fileserver. It is considered more critical for regulated industries such as, healthcare, finance and government where compliance requirements demand stringent tracking of user and system activates.This mitigation can be implemented through the following measures: 

System Audit:

- Use Case: Regularly assess system configurations to ensure compliance with organizational security policies.
- Implementation: Use tools to scan for deviations from established benchmarks.

Permission Audits:

- Use Case: Review file and folder permissions to minimize the risk of unauthorized access or privilege escalation.
- Implementation: Run access reviews to identify users or groups with excessive permissions.

Software Audits:

- Use Case: Identify outdated, unsupported, or insecure software that could serve as an attack vector.
- Implementation: Use inventory and vulnerability scanning tools to detect outdated versions and recommend secure alternatives.

Configuration Audits:

- Use Case: Evaluate system and network configurations to ensure secure settings (e.g., disabled SMBv1, enabled MFA).
- Implementation: Implement automated configuration scanning tools like SCAP (Security Content Automation Protocol) to identify non-compliant systems.

Network Audits:

- Use Case: Examine network traffic, firewall rules, and endpoint communications to identify unauthorized or insecure connections.
- Implementation: Utilize tools such as Wireshark, or Zeek to monitor and log suspicious network behavior.

### Sub: limit_access_to_resource_over_network [T1021.001]
**M1035 — Limit Access to Resource Over Network**

Restrict access to network resources, such as file shares, remote systems, and services, to only those users, accounts, or systems with a legitimate business requirement. This can include employing technologies like network concentrators, RDP gateways, and zero-trust network access (ZTNA) models, alongside hardening services and protocols. This mitigation can be implemented through the following measures:

Audit and Restrict Access:

- Regularly audit permissions for file shares, network services, and remote access tools.
- Remove unnecessary access and enforce least privilege principles for users and services.
- Use Active Directory and IAM tools to restrict access based on roles and attributes.

Deploy Secure Remote Access Solutions:

- Use RDP gateways, VPN concentrators, and ZTNA solutions to aggregate and secure remote access connections.
- Configure access controls to restrict connections based on time, device, and user identity.
- Enforce MFA for all remote access mechanisms.

Disable Unnecessary Services:

- Identify running services using tools like netstat (Windows/Linux) or Nmap.
- Disable unused services, such as Telnet, FTP, and legacy SMB, to reduce the attack surface.
- Use firewall rules to block traffic on unused ports and protocols.

Network Segmentation and Isolation:

- Use VLANs, firewalls, or micro-segmentation to isolate critical network resources from general access.
- Restrict communication between subnets to prevent lateral movement.

Monitor and Log Access:

- Monitor access attempts to file shares, RDP, and remote network resources using SIEM tools.
- Enable auditing and logging for successful and failed attempts to access restricted resources.

*Tools for Implementation*

File Share Management:

- Microsoft Active Directory Group Policies
- Samba (Linux/Unix file share management)
- AccessEnum (Windows access auditing tool)

Secure Remote Access:

- Microsoft Remote Desktop Gateway
- Apache Guacamole (open-source RDP/VNC gateway)
- Zero Trust solutions: Tailscale, Cloudflare Zero Trust

Service and Protocol Hardening:

- Nmap or Nessus for network service discovery
- Windows Group Policy Editor for disabling SMBv1, Telnet, and legacy protocols
- iptables or firewalld (Linux) for blocking unnecessary traffic

Network Segmentation:

- pfSense for open-source network isolation

### Sub: network_segmentation [T1021.001]
**M1030 — Network Segmentation**

Network segmentation involves dividing a network into smaller, isolated segments to control and limit the flow of traffic between devices, systems, and applications. By segmenting networks, organizations can reduce the attack surface, restrict lateral movement by adversaries, and protect critical assets from compromise.

Effective network segmentation leverages a combination of physical boundaries, logical separation through VLANs, and access control policies enforced by network appliances like firewalls, routers, and cloud-based configurations. This mitigation can be implemented through the following measures:

Segment Critical Systems:

- Identify and group systems based on their function, sensitivity, and risk. Examples include payment systems, HR databases, production systems, and internet-facing servers.
- Use VLANs, firewalls, or routers to enforce logical separation.

Implement DMZ for Public-Facing Services:

- Host web servers, DNS servers, and email servers in a DMZ to limit their access to internal systems.
- Apply strict firewall rules to filter traffic between the DMZ and internal networks.

Use Cloud-Based Segmentation:

- In cloud environments, use VPCs, subnets, and security groups to isolate applications and enforce traffic rules.
- Apply AWS Transit Gateway or Azure VNet peering for controlled connectivity between cloud segments.

Apply Microsegmentation for Workloads:

- Use software-defined networking (SDN) tools to implement workload-level segmentation and prevent lateral movement.

Restrict Traffic with ACLs and Firewalls:

- Apply Access Control Lists (ACLs) to network devices to enforce "deny by default" policies.
- Use firewalls to restrict both north-south (external-internal) and east-west (internal-internal) traffic.

Monitor and Audit Segmented Networks:

- Regularly review firewall rules, ACLs, and segmentation policies.
- Monitor network flows for anomalies to ensure segmentation is effective.

Test Segmentation Effectiveness:

- Perform periodic penetration tests to verify that unauthorized access is blocked between network segments.

### Sub: operating_system_configuration [T1021.001]
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

### Sub: disable_or_remove_feature_or_program [T1021.001]
**M1042 — Disable or Remove Feature or Program**

Disable or remove unnecessary and potentially vulnerable software, features, or services to reduce the attack surface and prevent abuse by adversaries. This involves identifying software or features that are no longer needed or that could be exploited and ensuring they are either removed or properly disabled. This mitigation can be implemented through the following measures: 

Remove Legacy Software:

- Use Case: Disable or remove older versions of software that no longer receive updates or security patches (e.g., legacy Java, Adobe Flash).
- Implementation: A company removes Flash Player from all employee systems after it has reached its end-of-life date.

Disable Unused Features:

- Use Case: Turn off unnecessary operating system features like SMBv1, Telnet, or RDP if they are not required.
- Implementation: Disable SMBv1 in a Windows environment to mitigate vulnerabilities like EternalBlue.

Control Applications Installed by Users:

- Use Case: Prevent users from installing unauthorized software via group policies or other management tools.
- Implementation: Block user installations of unauthorized file-sharing applications (e.g., BitTorrent clients) in an enterprise environment.

Remove Unnecessary Services:

- Use Case: Identify and disable unnecessary default services running on endpoints, servers, or network devices.
- Implementation: Disable unused administrative shares (e.g., C$, ADMIN$) on workstations.

Restrict Add-ons and Plugins:

- Use Case: Remove or disable browser plugins and add-ons that are not needed for business purposes.
- Implementation: Disable Java and ActiveX plugins in web browsers to prevent drive-by attacks.

### Sub: user_account_management [T1021.001]
**M1018 — User Account Management**

User Account Management involves implementing and enforcing policies for the lifecycle of user accounts, including creation, modification, and deactivation. Proper account management reduces the attack surface by limiting unauthorized access, managing account privileges, and ensuring accounts are used according to organizational policies. This mitigation can be implemented through the following measures:

Enforcing the Principle of Least Privilege

- Implementation: Assign users only the minimum permissions required to perform their job functions. Regularly audit accounts to ensure no excess permissions are granted.
- Use Case: Reduces the risk of privilege escalation by ensuring accounts cannot perform unauthorized actions.

Implementing Strong Password Policies

- Implementation: Enforce password complexity requirements (e.g., length, character types). Require password expiration every 90 days and disallow password reuse.
- Use Case: Prevents adversaries from gaining unauthorized access through password guessing or brute force attacks.

Managing Dormant and Orphaned Accounts

- Implementation: Implement automated workflows to disable accounts after a set period of inactivity (e.g., 30 days). Remove orphaned accounts (e.g., accounts without an assigned owner) during regular account audits.
- Use Case: Eliminates dormant accounts that could be exploited by attackers.

Account Lockout Policies

- Implementation: Configure account lockout thresholds (e.g., lock accounts after five failed login attempts). Set lockout durations to a minimum of 15 minutes.
- Use Case: Mitigates automated attack techniques that rely on repeated login attempts.

Multi-Factor Authentication (MFA) for High-Risk Accounts

- Implementation: Require MFA for all administrative accounts and high-risk users. Use MFA mechanisms like hardware tokens, authenticator apps, or biometrics.
- Use Case: Prevents unauthorized access, even if credentials are stolen.

Restricting Interactive Logins

- Implementation: Restrict interactive logins for privileged accounts to specific secure systems or management consoles. Use group policies to enforce logon restrictions.
- Use Case: Protects sensitive accounts from misuse or exploitation.

*Tools for Implementation*

Built-in Tools:

- Microsoft Active Directory (AD): Centralized account management and RBAC enforcement.
- Group Policy Object (GPO): Enforce password policies, logon restrictions, and account lockout policies.

Identity and Access Management (IAM) Tools:

- Okta: Centralized user provisioning, MFA, and SSO integration.
- Microsoft Azure Active Directory: Provides advanced account lifecycle management, role-based access, and conditional access policies.

Privileged Account Management (PAM):
- CyberArk, BeyondTrust, Thycotic: Manage and monitor privileged account usage, enforce session recording, and JIT access.

### Sub: multi-factor_authentication [T1021.001]
**M1032 — Multi-factor Authentication**

Multi-Factor Authentication (MFA) enhances security by requiring users to provide at least two forms of verification to prove their identity before granting access. These factors typically include:

- *Something you know*: Passwords, PINs.
- *Something you have*: Physical tokens, smartphone authenticator apps.
- *Something you are*: Biometric data such as fingerprints, facial recognition, or retinal scans.

Implementing MFA across all critical systems and services ensures robust protection against account takeover and unauthorized access. This mitigation can be implemented through the following measures:

Identity and Access Management (IAM):

- Use IAM solutions like Azure Active Directory, Okta, or AWS IAM to enforce MFA policies for all user logins, especially for privileged roles.
- Enable conditional access policies to enforce MFA for risky sign-ins (e.g., unfamiliar devices, geolocations).
- Enable Conditional Access policies to only allow logins from trusted devices, such as those enrolled in Intune or joined via Hybrid/Entra.

Authentication Tools and Methods:

- Use authenticator applications such as Google Authenticator, Microsoft Authenticator, or Authy for time-based one-time passwords (TOTP).
- Deploy hardware-based tokens like YubiKey, RSA SecurID, or smart cards for additional security.
- Enforce biometric authentication for compatible devices and applications.

Secure Legacy Systems:

- Integrate MFA solutions with older systems using third-party tools like Duo Security or Thales SafeNet.
- Enable RADIUS/NPS servers to facilitate MFA for VPNs, RDP, and other network logins.

Monitoring and Alerting:

- Use SIEM tools to monitor failed MFA attempts, login anomalies, or brute-force attempts against MFA systems.
- Implement alerts for suspicious MFA activities, such as repeated failed codes or new device registrations.

Training and Policy Enforcement:

- Educate employees on the importance of MFA and secure authenticator usage.
- Enforce policies that require MFA on all critical systems, especially for remote access, privileged accounts, and cloud applications.

### Sub: privileged_account_management [T1021.001]
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

## Phase: eradication
### Sub: audit [T1021.001]
**M1047 — Audit**

Auditing is the process of recording activity and systematically reviewing and analyzing the activity and system configurations. The primary purpose of auditing is to detect anomalies and identify potential threats or weaknesses in the environment. Proper auditing configurations can also help to meet compliance requirements. The process of auditing encompasses regular analysis of user behaviors and system logs in support of proactive security measures.

Auditing is applicable to all systems used within an organization, from the front door of a building to accessing a file on a fileserver. It is considered more critical for regulated industries such as, healthcare, finance and government where compliance requirements demand stringent tracking of user and system activates.This mitigation can be implemented through the following measures: 

System Audit:

- Use Case: Regularly assess system configurations to ensure compliance with organizational security policies.
- Implementation: Use tools to scan for deviations from established benchmarks.

Permission Audits:

- Use Case: Review file and folder permissions to minimize the risk of unauthorized access or privilege escalation.
- Implementation: Run access reviews to identify users or groups with excessive permissions.

Software Audits:

- Use Case: Identify outdated, unsupported, or insecure software that could serve as an attack vector.
- Implementation: Use inventory and vulnerability scanning tools to detect outdated versions and recommend secure alternatives.

Configuration Audits:

- Use Case: Evaluate system and network configurations to ensure secure settings (e.g., disabled SMBv1, enabled MFA).
- Implementation: Implement automated configuration scanning tools like SCAP (Security Content Automation Protocol) to identify non-compliant systems.

Network Audits:

- Use Case: Examine network traffic, firewall rules, and endpoint communications to identify unauthorized or insecure connections.
- Implementation: Utilize tools such as Wireshark, or Zeek to monitor and log suspicious network behavior.

### Sub: limit_access_to_resource_over_network [T1021.001]
**M1035 — Limit Access to Resource Over Network**

Restrict access to network resources, such as file shares, remote systems, and services, to only those users, accounts, or systems with a legitimate business requirement. This can include employing technologies like network concentrators, RDP gateways, and zero-trust network access (ZTNA) models, alongside hardening services and protocols. This mitigation can be implemented through the following measures:

Audit and Restrict Access:

- Regularly audit permissions for file shares, network services, and remote access tools.
- Remove unnecessary access and enforce least privilege principles for users and services.
- Use Active Directory and IAM tools to restrict access based on roles and attributes.

Deploy Secure Remote Access Solutions:

- Use RDP gateways, VPN concentrators, and ZTNA solutions to aggregate and secure remote access connections.
- Configure access controls to restrict connections based on time, device, and user identity.
- Enforce MFA for all remote access mechanisms.

Disable Unnecessary Services:

- Identify running services using tools like netstat (Windows/Linux) or Nmap.
- Disable unused services, such as Telnet, FTP, and legacy SMB, to reduce the attack surface.
- Use firewall rules to block traffic on unused ports and protocols.

Network Segmentation and Isolation:

- Use VLANs, firewalls, or micro-segmentation to isolate critical network resources from general access.
- Restrict communication between subnets to prevent lateral movement.

Monitor and Log Access:

- Monitor access attempts to file shares, RDP, and remote network resources using SIEM tools.
- Enable auditing and logging for successful and failed attempts to access restricted resources.

*Tools for Implementation*

File Share Management:

- Microsoft Active Directory Group Policies
- Samba (Linux/Unix file share management)
- AccessEnum (Windows access auditing tool)

Secure Remote Access:

- Microsoft Remote Desktop Gateway
- Apache Guacamole (open-source RDP/VNC gateway)
- Zero Trust solutions: Tailscale, Cloudflare Zero Trust

Service and Protocol Hardening:

- Nmap or Nessus for network service discovery
- Windows Group Policy Editor for disabling SMBv1, Telnet, and legacy protocols
- iptables or firewalld (Linux) for blocking unnecessary traffic

Network Segmentation:

- pfSense for open-source network isolation

### Sub: network_segmentation [T1021.001]
**M1030 — Network Segmentation**

Network segmentation involves dividing a network into smaller, isolated segments to control and limit the flow of traffic between devices, systems, and applications. By segmenting networks, organizations can reduce the attack surface, restrict lateral movement by adversaries, and protect critical assets from compromise.

Effective network segmentation leverages a combination of physical boundaries, logical separation through VLANs, and access control policies enforced by network appliances like firewalls, routers, and cloud-based configurations. This mitigation can be implemented through the following measures:

Segment Critical Systems:

- Identify and group systems based on their function, sensitivity, and risk. Examples include payment systems, HR databases, production systems, and internet-facing servers.
- Use VLANs, firewalls, or routers to enforce logical separation.

Implement DMZ for Public-Facing Services:

- Host web servers, DNS servers, and email servers in a DMZ to limit their access to internal systems.
- Apply strict firewall rules to filter traffic between the DMZ and internal networks.

Use Cloud-Based Segmentation:

- In cloud environments, use VPCs, subnets, and security groups to isolate applications and enforce traffic rules.
- Apply AWS Transit Gateway or Azure VNet peering for controlled connectivity between cloud segments.

Apply Microsegmentation for Workloads:

- Use software-defined networking (SDN) tools to implement workload-level segmentation and prevent lateral movement.

Restrict Traffic with ACLs and Firewalls:

- Apply Access Control Lists (ACLs) to network devices to enforce "deny by default" policies.
- Use firewalls to restrict both north-south (external-internal) and east-west (internal-internal) traffic.

Monitor and Audit Segmented Networks:

- Regularly review firewall rules, ACLs, and segmentation policies.
- Monitor network flows for anomalies to ensure segmentation is effective.

Test Segmentation Effectiveness:

- Perform periodic penetration tests to verify that unauthorized access is blocked between network segments.

### Sub: operating_system_configuration [T1021.001]
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

### Sub: disable_or_remove_feature_or_program [T1021.001]
**M1042 — Disable or Remove Feature or Program**

Disable or remove unnecessary and potentially vulnerable software, features, or services to reduce the attack surface and prevent abuse by adversaries. This involves identifying software or features that are no longer needed or that could be exploited and ensuring they are either removed or properly disabled. This mitigation can be implemented through the following measures: 

Remove Legacy Software:

- Use Case: Disable or remove older versions of software that no longer receive updates or security patches (e.g., legacy Java, Adobe Flash).
- Implementation: A company removes Flash Player from all employee systems after it has reached its end-of-life date.

Disable Unused Features:

- Use Case: Turn off unnecessary operating system features like SMBv1, Telnet, or RDP if they are not required.
- Implementation: Disable SMBv1 in a Windows environment to mitigate vulnerabilities like EternalBlue.

Control Applications Installed by Users:

- Use Case: Prevent users from installing unauthorized software via group policies or other management tools.
- Implementation: Block user installations of unauthorized file-sharing applications (e.g., BitTorrent clients) in an enterprise environment.

Remove Unnecessary Services:

- Use Case: Identify and disable unnecessary default services running on endpoints, servers, or network devices.
- Implementation: Disable unused administrative shares (e.g., C$, ADMIN$) on workstations.

Restrict Add-ons and Plugins:

- Use Case: Remove or disable browser plugins and add-ons that are not needed for business purposes.
- Implementation: Disable Java and ActiveX plugins in web browsers to prevent drive-by attacks.

### Sub: user_account_management [T1021.001]
**M1018 — User Account Management**

User Account Management involves implementing and enforcing policies for the lifecycle of user accounts, including creation, modification, and deactivation. Proper account management reduces the attack surface by limiting unauthorized access, managing account privileges, and ensuring accounts are used according to organizational policies. This mitigation can be implemented through the following measures:

Enforcing the Principle of Least Privilege

- Implementation: Assign users only the minimum permissions required to perform their job functions. Regularly audit accounts to ensure no excess permissions are granted.
- Use Case: Reduces the risk of privilege escalation by ensuring accounts cannot perform unauthorized actions.

Implementing Strong Password Policies

- Implementation: Enforce password complexity requirements (e.g., length, character types). Require password expiration every 90 days and disallow password reuse.
- Use Case: Prevents adversaries from gaining unauthorized access through password guessing or brute force attacks.

Managing Dormant and Orphaned Accounts

- Implementation: Implement automated workflows to disable accounts after a set period of inactivity (e.g., 30 days). Remove orphaned accounts (e.g., accounts without an assigned owner) during regular account audits.
- Use Case: Eliminates dormant accounts that could be exploited by attackers.

Account Lockout Policies

- Implementation: Configure account lockout thresholds (e.g., lock accounts after five failed login attempts). Set lockout durations to a minimum of 15 minutes.
- Use Case: Mitigates automated attack techniques that rely on repeated login attempts.

Multi-Factor Authentication (MFA) for High-Risk Accounts

- Implementation: Require MFA for all administrative accounts and high-risk users. Use MFA mechanisms like hardware tokens, authenticator apps, or biometrics.
- Use Case: Prevents unauthorized access, even if credentials are stolen.

Restricting Interactive Logins

- Implementation: Restrict interactive logins for privileged accounts to specific secure systems or management consoles. Use group policies to enforce logon restrictions.
- Use Case: Protects sensitive accounts from misuse or exploitation.

*Tools for Implementation*

Built-in Tools:

- Microsoft Active Directory (AD): Centralized account management and RBAC enforcement.
- Group Policy Object (GPO): Enforce password policies, logon restrictions, and account lockout policies.

Identity and Access Management (IAM) Tools:

- Okta: Centralized user provisioning, MFA, and SSO integration.
- Microsoft Azure Active Directory: Provides advanced account lifecycle management, role-based access, and conditional access policies.

Privileged Account Management (PAM):
- CyberArk, BeyondTrust, Thycotic: Manage and monitor privileged account usage, enforce session recording, and JIT access.

### Sub: multi-factor_authentication [T1021.001]
**M1032 — Multi-factor Authentication**

Multi-Factor Authentication (MFA) enhances security by requiring users to provide at least two forms of verification to prove their identity before granting access. These factors typically include:

- *Something you know*: Passwords, PINs.
- *Something you have*: Physical tokens, smartphone authenticator apps.
- *Something you are*: Biometric data such as fingerprints, facial recognition, or retinal scans.

Implementing MFA across all critical systems and services ensures robust protection against account takeover and unauthorized access. This mitigation can be implemented through the following measures:

Identity and Access Management (IAM):

- Use IAM solutions like Azure Active Directory, Okta, or AWS IAM to enforce MFA policies for all user logins, especially for privileged roles.
- Enable conditional access policies to enforce MFA for risky sign-ins (e.g., unfamiliar devices, geolocations).
- Enable Conditional Access policies to only allow logins from trusted devices, such as those enrolled in Intune or joined via Hybrid/Entra.

Authentication Tools and Methods:

- Use authenticator applications such as Google Authenticator, Microsoft Authenticator, or Authy for time-based one-time passwords (TOTP).
- Deploy hardware-based tokens like YubiKey, RSA SecurID, or smart cards for additional security.
- Enforce biometric authentication for compatible devices and applications.

Secure Legacy Systems:

- Integrate MFA solutions with older systems using third-party tools like Duo Security or Thales SafeNet.
- Enable RADIUS/NPS servers to facilitate MFA for VPNs, RDP, and other network logins.

Monitoring and Alerting:

- Use SIEM tools to monitor failed MFA attempts, login anomalies, or brute-force attempts against MFA systems.
- Implement alerts for suspicious MFA activities, such as repeated failed codes or new device registrations.

Training and Policy Enforcement:

- Educate employees on the importance of MFA and secure authenticator usage.
- Enforce policies that require MFA on all critical systems, especially for remote access, privileged accounts, and cloud applications.

### Sub: privileged_account_management [T1021.001]
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

## Phase: recovery
### Sub: audit [T1021.001]
**M1047 — Audit**

Auditing is the process of recording activity and systematically reviewing and analyzing the activity and system configurations. The primary purpose of auditing is to detect anomalies and identify potential threats or weaknesses in the environment. Proper auditing configurations can also help to meet compliance requirements. The process of auditing encompasses regular analysis of user behaviors and system logs in support of proactive security measures.

Auditing is applicable to all systems used within an organization, from the front door of a building to accessing a file on a fileserver. It is considered more critical for regulated industries such as, healthcare, finance and government where compliance requirements demand stringent tracking of user and system activates.This mitigation can be implemented through the following measures: 

System Audit:

- Use Case: Regularly assess system configurations to ensure compliance with organizational security policies.
- Implementation: Use tools to scan for deviations from established benchmarks.

Permission Audits:

- Use Case: Review file and folder permissions to minimize the risk of unauthorized access or privilege escalation.
- Implementation: Run access reviews to identify users or groups with excessive permissions.

Software Audits:

- Use Case: Identify outdated, unsupported, or insecure software that could serve as an attack vector.
- Implementation: Use inventory and vulnerability scanning tools to detect outdated versions and recommend secure alternatives.

Configuration Audits:

- Use Case: Evaluate system and network configurations to ensure secure settings (e.g., disabled SMBv1, enabled MFA).
- Implementation: Implement automated configuration scanning tools like SCAP (Security Content Automation Protocol) to identify non-compliant systems.

Network Audits:

- Use Case: Examine network traffic, firewall rules, and endpoint communications to identify unauthorized or insecure connections.
- Implementation: Utilize tools such as Wireshark, or Zeek to monitor and log suspicious network behavior.

### Sub: limit_access_to_resource_over_network [T1021.001]
**M1035 — Limit Access to Resource Over Network**

Restrict access to network resources, such as file shares, remote systems, and services, to only those users, accounts, or systems with a legitimate business requirement. This can include employing technologies like network concentrators, RDP gateways, and zero-trust network access (ZTNA) models, alongside hardening services and protocols. This mitigation can be implemented through the following measures:

Audit and Restrict Access:

- Regularly audit permissions for file shares, network services, and remote access tools.
- Remove unnecessary access and enforce least privilege principles for users and services.
- Use Active Directory and IAM tools to restrict access based on roles and attributes.

Deploy Secure Remote Access Solutions:

- Use RDP gateways, VPN concentrators, and ZTNA solutions to aggregate and secure remote access connections.
- Configure access controls to restrict connections based on time, device, and user identity.
- Enforce MFA for all remote access mechanisms.

Disable Unnecessary Services:

- Identify running services using tools like netstat (Windows/Linux) or Nmap.
- Disable unused services, such as Telnet, FTP, and legacy SMB, to reduce the attack surface.
- Use firewall rules to block traffic on unused ports and protocols.

Network Segmentation and Isolation:

- Use VLANs, firewalls, or micro-segmentation to isolate critical network resources from general access.
- Restrict communication between subnets to prevent lateral movement.

Monitor and Log Access:

- Monitor access attempts to file shares, RDP, and remote network resources using SIEM tools.
- Enable auditing and logging for successful and failed attempts to access restricted resources.

*Tools for Implementation*

File Share Management:

- Microsoft Active Directory Group Policies
- Samba (Linux/Unix file share management)
- AccessEnum (Windows access auditing tool)

Secure Remote Access:

- Microsoft Remote Desktop Gateway
- Apache Guacamole (open-source RDP/VNC gateway)
- Zero Trust solutions: Tailscale, Cloudflare Zero Trust

Service and Protocol Hardening:

- Nmap or Nessus for network service discovery
- Windows Group Policy Editor for disabling SMBv1, Telnet, and legacy protocols
- iptables or firewalld (Linux) for blocking unnecessary traffic

Network Segmentation:

- pfSense for open-source network isolation

### Sub: network_segmentation [T1021.001]
**M1030 — Network Segmentation**

Network segmentation involves dividing a network into smaller, isolated segments to control and limit the flow of traffic between devices, systems, and applications. By segmenting networks, organizations can reduce the attack surface, restrict lateral movement by adversaries, and protect critical assets from compromise.

Effective network segmentation leverages a combination of physical boundaries, logical separation through VLANs, and access control policies enforced by network appliances like firewalls, routers, and cloud-based configurations. This mitigation can be implemented through the following measures:

Segment Critical Systems:

- Identify and group systems based on their function, sensitivity, and risk. Examples include payment systems, HR databases, production systems, and internet-facing servers.
- Use VLANs, firewalls, or routers to enforce logical separation.

Implement DMZ for Public-Facing Services:

- Host web servers, DNS servers, and email servers in a DMZ to limit their access to internal systems.
- Apply strict firewall rules to filter traffic between the DMZ and internal networks.

Use Cloud-Based Segmentation:

- In cloud environments, use VPCs, subnets, and security groups to isolate applications and enforce traffic rules.
- Apply AWS Transit Gateway or Azure VNet peering for controlled connectivity between cloud segments.

Apply Microsegmentation for Workloads:

- Use software-defined networking (SDN) tools to implement workload-level segmentation and prevent lateral movement.

Restrict Traffic with ACLs and Firewalls:

- Apply Access Control Lists (ACLs) to network devices to enforce "deny by default" policies.
- Use firewalls to restrict both north-south (external-internal) and east-west (internal-internal) traffic.

Monitor and Audit Segmented Networks:

- Regularly review firewall rules, ACLs, and segmentation policies.
- Monitor network flows for anomalies to ensure segmentation is effective.

Test Segmentation Effectiveness:

- Perform periodic penetration tests to verify that unauthorized access is blocked between network segments.

### Sub: operating_system_configuration [T1021.001]
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

### Sub: disable_or_remove_feature_or_program [T1021.001]
**M1042 — Disable or Remove Feature or Program**

Disable or remove unnecessary and potentially vulnerable software, features, or services to reduce the attack surface and prevent abuse by adversaries. This involves identifying software or features that are no longer needed or that could be exploited and ensuring they are either removed or properly disabled. This mitigation can be implemented through the following measures: 

Remove Legacy Software:

- Use Case: Disable or remove older versions of software that no longer receive updates or security patches (e.g., legacy Java, Adobe Flash).
- Implementation: A company removes Flash Player from all employee systems after it has reached its end-of-life date.

Disable Unused Features:

- Use Case: Turn off unnecessary operating system features like SMBv1, Telnet, or RDP if they are not required.
- Implementation: Disable SMBv1 in a Windows environment to mitigate vulnerabilities like EternalBlue.

Control Applications Installed by Users:

- Use Case: Prevent users from installing unauthorized software via group policies or other management tools.
- Implementation: Block user installations of unauthorized file-sharing applications (e.g., BitTorrent clients) in an enterprise environment.

Remove Unnecessary Services:

- Use Case: Identify and disable unnecessary default services running on endpoints, servers, or network devices.
- Implementation: Disable unused administrative shares (e.g., C$, ADMIN$) on workstations.

Restrict Add-ons and Plugins:

- Use Case: Remove or disable browser plugins and add-ons that are not needed for business purposes.
- Implementation: Disable Java and ActiveX plugins in web browsers to prevent drive-by attacks.

### Sub: user_account_management [T1021.001]
**M1018 — User Account Management**

User Account Management involves implementing and enforcing policies for the lifecycle of user accounts, including creation, modification, and deactivation. Proper account management reduces the attack surface by limiting unauthorized access, managing account privileges, and ensuring accounts are used according to organizational policies. This mitigation can be implemented through the following measures:

Enforcing the Principle of Least Privilege

- Implementation: Assign users only the minimum permissions required to perform their job functions. Regularly audit accounts to ensure no excess permissions are granted.
- Use Case: Reduces the risk of privilege escalation by ensuring accounts cannot perform unauthorized actions.

Implementing Strong Password Policies

- Implementation: Enforce password complexity requirements (e.g., length, character types). Require password expiration every 90 days and disallow password reuse.
- Use Case: Prevents adversaries from gaining unauthorized access through password guessing or brute force attacks.

Managing Dormant and Orphaned Accounts

- Implementation: Implement automated workflows to disable accounts after a set period of inactivity (e.g., 30 days). Remove orphaned accounts (e.g., accounts without an assigned owner) during regular account audits.
- Use Case: Eliminates dormant accounts that could be exploited by attackers.

Account Lockout Policies

- Implementation: Configure account lockout thresholds (e.g., lock accounts after five failed login attempts). Set lockout durations to a minimum of 15 minutes.
- Use Case: Mitigates automated attack techniques that rely on repeated login attempts.

Multi-Factor Authentication (MFA) for High-Risk Accounts

- Implementation: Require MFA for all administrative accounts and high-risk users. Use MFA mechanisms like hardware tokens, authenticator apps, or biometrics.
- Use Case: Prevents unauthorized access, even if credentials are stolen.

Restricting Interactive Logins

- Implementation: Restrict interactive logins for privileged accounts to specific secure systems or management consoles. Use group policies to enforce logon restrictions.
- Use Case: Protects sensitive accounts from misuse or exploitation.

*Tools for Implementation*

Built-in Tools:

- Microsoft Active Directory (AD): Centralized account management and RBAC enforcement.
- Group Policy Object (GPO): Enforce password policies, logon restrictions, and account lockout policies.

Identity and Access Management (IAM) Tools:

- Okta: Centralized user provisioning, MFA, and SSO integration.
- Microsoft Azure Active Directory: Provides advanced account lifecycle management, role-based access, and conditional access policies.

Privileged Account Management (PAM):
- CyberArk, BeyondTrust, Thycotic: Manage and monitor privileged account usage, enforce session recording, and JIT access.

### Sub: multi-factor_authentication [T1021.001]
**M1032 — Multi-factor Authentication**

Multi-Factor Authentication (MFA) enhances security by requiring users to provide at least two forms of verification to prove their identity before granting access. These factors typically include:

- *Something you know*: Passwords, PINs.
- *Something you have*: Physical tokens, smartphone authenticator apps.
- *Something you are*: Biometric data such as fingerprints, facial recognition, or retinal scans.

Implementing MFA across all critical systems and services ensures robust protection against account takeover and unauthorized access. This mitigation can be implemented through the following measures:

Identity and Access Management (IAM):

- Use IAM solutions like Azure Active Directory, Okta, or AWS IAM to enforce MFA policies for all user logins, especially for privileged roles.
- Enable conditional access policies to enforce MFA for risky sign-ins (e.g., unfamiliar devices, geolocations).
- Enable Conditional Access policies to only allow logins from trusted devices, such as those enrolled in Intune or joined via Hybrid/Entra.

Authentication Tools and Methods:

- Use authenticator applications such as Google Authenticator, Microsoft Authenticator, or Authy for time-based one-time passwords (TOTP).
- Deploy hardware-based tokens like YubiKey, RSA SecurID, or smart cards for additional security.
- Enforce biometric authentication for compatible devices and applications.

Secure Legacy Systems:

- Integrate MFA solutions with older systems using third-party tools like Duo Security or Thales SafeNet.
- Enable RADIUS/NPS servers to facilitate MFA for VPNs, RDP, and other network logins.

Monitoring and Alerting:

- Use SIEM tools to monitor failed MFA attempts, login anomalies, or brute-force attempts against MFA systems.
- Implement alerts for suspicious MFA activities, such as repeated failed codes or new device registrations.

Training and Policy Enforcement:

- Educate employees on the importance of MFA and secure authenticator usage.
- Enforce policies that require MFA on all critical systems, especially for remote access, privileged accounts, and cloud applications.

### Sub: privileged_account_management [T1021.001]
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
