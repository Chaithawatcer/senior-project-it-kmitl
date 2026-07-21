---
threat_name: "Pass the Hash"
technique_ids: ["T1550.002"]
severity: Medium
source_doc: "MITRE_ATTACK_Mitigations_T1550.002"
doc_type: mitre
---

> ที่มา: MITRE ATT&CK (T1550.002 — Pass the Hash) ดึงผ่าน mitreattack-python (offline)
> เนื้อหาด้านล่างคือคำอธิบายทางการจาก ATT&CK โดยตรง ไม่ได้เรียบเรียงใหม่
> เพื่อให้อ้างอิงย้อนกลับไปยังเอกสารต้นฉบับได้ตรง

## Phase: containment
### Sub: update_software [T1550.002]
**M1051 — Update Software**

Software updates ensure systems are protected against known vulnerabilities by applying patches and upgrades provided by vendors. Regular updates reduce the attack surface and prevent adversaries from exploiting known security gaps. This includes patching operating systems, applications, drivers, and firmware. This mitigation can be implemented through the following measures:

Regular Operating System Updates

- Implementation: Apply the latest Windows security updates monthly using WSUS (Windows Server Update Services) or a similar patch management solution. Configure systems to check for updates automatically and schedule reboots during maintenance windows.
- Use Case: Prevents exploitation of OS vulnerabilities such as privilege escalation or remote code execution.

Application Patching

- Implementation: Monitor Apache's update release notes for security patches addressing vulnerabilities. Schedule updates for off-peak hours to avoid downtime while maintaining security compliance.
- Use Case: Prevents exploitation of web application vulnerabilities, such as those leading to unauthorized access or data breaches.

Firmware Updates

- Implementation: Regularly check the vendor’s website for firmware updates addressing vulnerabilities. Plan for update deployment during scheduled maintenance to minimize business disruption.
- Use Case: Protects against vulnerabilities that adversaries could exploit to gain access to network devices or inject malicious traffic.

Emergency Patch Deployment

- Implementation: Use the emergency patch deployment feature of the organization's patch management tool to apply updates to all affected Exchange servers within 24 hours.
- Use Case: Reduces the risk of exploitation by rapidly addressing critical vulnerabilities.

Centralized Patch Management

- Implementation: Implement a centralized patch management system, such as SCCM or ManageEngine, to automate and track patch deployment across all environments. Generate regular compliance reports to ensure all systems are updated.
- Use Case: Streamlines patching processes and ensures no critical systems are missed.

*Tools for Implementation*

Patch Management Tools:

- WSUS: Manage and deploy Microsoft updates across the organization.
- ManageEngine Patch Manager Plus: Automate patch deployment for OS and third-party apps.
- Ansible: Automate updates across multiple platforms, including Linux and Windows.

Vulnerability Scanning Tools:

- OpenVAS: Open-source vulnerability scanning to identify missing patches.

### Sub: user_account_control [T1550.002]
**M1052 — User Account Control**

User Account Control (UAC) is a security feature in Microsoft Windows that prevents unauthorized changes to the operating system. UAC prompts users to confirm or provide administrator credentials when an action requires elevated privileges. Proper configuration of UAC reduces the risk of privilege escalation attacks. This mitigation can be implemented through the following measures:

Enable UAC Globally:

- Ensure UAC is enabled through Group Policy by setting `User Account Control: Run all administrators in Admin Approval Mode` to `Enabled`.

Require Credential Prompt:

- Use Group Policy to configure UAC to prompt for administrative credentials instead of just confirmation (`User Account Control: Behavior of the elevation prompt`).

Restrict Built-in Administrator Account:

Set `Admin Approval Mode` for the built-in Administrator account to `Enabled` in Group Policy.

Secure the UAC Prompt:

- Configure UAC prompts to display on the secure desktop (`User Account Control: Switch to the secure desktop when prompting for elevation`).

Prevent UAC Bypass:

- Block untrusted applications from triggering UAC prompts by configuring `User Account Control: Only elevate executables that are signed and validated`.
- Use EDR tools to detect and block known UAC bypass techniques.

Monitor UAC-Related Events:

- Use Windows Event Viewer to monitor for event ID 4688 (process creation) and look for suspicious processes attempting to invoke UAC elevation.

*Tools for Implementation*

Built-in Windows Tools:

- Group Policy Editor: Configure UAC settings centrally for enterprise environments.
- Registry Editor: Modify UAC-related settings directly, such as `EnableLUA` and `ConsentPromptBehaviorAdmin`.

Endpoint Security Solutions:

- Microsoft Defender for Endpoint: Detects and blocks UAC bypass techniques.
- Sysmon: Logs process creations and monitors UAC elevation attempts for suspicious activity.

Third-Party Security Tools:

- Process Monitor (Sysinternals): Tracks real-time processes interacting with UAC.
- EventSentry: Monitors Windows Event Logs for UAC-related alerts.

### Sub: user_account_management [T1550.002]
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

### Sub: privileged_account_management [T1550.002]
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
### Sub: update_software [T1550.002]
**M1051 — Update Software**

Software updates ensure systems are protected against known vulnerabilities by applying patches and upgrades provided by vendors. Regular updates reduce the attack surface and prevent adversaries from exploiting known security gaps. This includes patching operating systems, applications, drivers, and firmware. This mitigation can be implemented through the following measures:

Regular Operating System Updates

- Implementation: Apply the latest Windows security updates monthly using WSUS (Windows Server Update Services) or a similar patch management solution. Configure systems to check for updates automatically and schedule reboots during maintenance windows.
- Use Case: Prevents exploitation of OS vulnerabilities such as privilege escalation or remote code execution.

Application Patching

- Implementation: Monitor Apache's update release notes for security patches addressing vulnerabilities. Schedule updates for off-peak hours to avoid downtime while maintaining security compliance.
- Use Case: Prevents exploitation of web application vulnerabilities, such as those leading to unauthorized access or data breaches.

Firmware Updates

- Implementation: Regularly check the vendor’s website for firmware updates addressing vulnerabilities. Plan for update deployment during scheduled maintenance to minimize business disruption.
- Use Case: Protects against vulnerabilities that adversaries could exploit to gain access to network devices or inject malicious traffic.

Emergency Patch Deployment

- Implementation: Use the emergency patch deployment feature of the organization's patch management tool to apply updates to all affected Exchange servers within 24 hours.
- Use Case: Reduces the risk of exploitation by rapidly addressing critical vulnerabilities.

Centralized Patch Management

- Implementation: Implement a centralized patch management system, such as SCCM or ManageEngine, to automate and track patch deployment across all environments. Generate regular compliance reports to ensure all systems are updated.
- Use Case: Streamlines patching processes and ensures no critical systems are missed.

*Tools for Implementation*

Patch Management Tools:

- WSUS: Manage and deploy Microsoft updates across the organization.
- ManageEngine Patch Manager Plus: Automate patch deployment for OS and third-party apps.
- Ansible: Automate updates across multiple platforms, including Linux and Windows.

Vulnerability Scanning Tools:

- OpenVAS: Open-source vulnerability scanning to identify missing patches.

### Sub: user_account_control [T1550.002]
**M1052 — User Account Control**

User Account Control (UAC) is a security feature in Microsoft Windows that prevents unauthorized changes to the operating system. UAC prompts users to confirm or provide administrator credentials when an action requires elevated privileges. Proper configuration of UAC reduces the risk of privilege escalation attacks. This mitigation can be implemented through the following measures:

Enable UAC Globally:

- Ensure UAC is enabled through Group Policy by setting `User Account Control: Run all administrators in Admin Approval Mode` to `Enabled`.

Require Credential Prompt:

- Use Group Policy to configure UAC to prompt for administrative credentials instead of just confirmation (`User Account Control: Behavior of the elevation prompt`).

Restrict Built-in Administrator Account:

Set `Admin Approval Mode` for the built-in Administrator account to `Enabled` in Group Policy.

Secure the UAC Prompt:

- Configure UAC prompts to display on the secure desktop (`User Account Control: Switch to the secure desktop when prompting for elevation`).

Prevent UAC Bypass:

- Block untrusted applications from triggering UAC prompts by configuring `User Account Control: Only elevate executables that are signed and validated`.
- Use EDR tools to detect and block known UAC bypass techniques.

Monitor UAC-Related Events:

- Use Windows Event Viewer to monitor for event ID 4688 (process creation) and look for suspicious processes attempting to invoke UAC elevation.

*Tools for Implementation*

Built-in Windows Tools:

- Group Policy Editor: Configure UAC settings centrally for enterprise environments.
- Registry Editor: Modify UAC-related settings directly, such as `EnableLUA` and `ConsentPromptBehaviorAdmin`.

Endpoint Security Solutions:

- Microsoft Defender for Endpoint: Detects and blocks UAC bypass techniques.
- Sysmon: Logs process creations and monitors UAC elevation attempts for suspicious activity.

Third-Party Security Tools:

- Process Monitor (Sysinternals): Tracks real-time processes interacting with UAC.
- EventSentry: Monitors Windows Event Logs for UAC-related alerts.

### Sub: user_account_management [T1550.002]
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

### Sub: privileged_account_management [T1550.002]
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
### Sub: update_software [T1550.002]
**M1051 — Update Software**

Software updates ensure systems are protected against known vulnerabilities by applying patches and upgrades provided by vendors. Regular updates reduce the attack surface and prevent adversaries from exploiting known security gaps. This includes patching operating systems, applications, drivers, and firmware. This mitigation can be implemented through the following measures:

Regular Operating System Updates

- Implementation: Apply the latest Windows security updates monthly using WSUS (Windows Server Update Services) or a similar patch management solution. Configure systems to check for updates automatically and schedule reboots during maintenance windows.
- Use Case: Prevents exploitation of OS vulnerabilities such as privilege escalation or remote code execution.

Application Patching

- Implementation: Monitor Apache's update release notes for security patches addressing vulnerabilities. Schedule updates for off-peak hours to avoid downtime while maintaining security compliance.
- Use Case: Prevents exploitation of web application vulnerabilities, such as those leading to unauthorized access or data breaches.

Firmware Updates

- Implementation: Regularly check the vendor’s website for firmware updates addressing vulnerabilities. Plan for update deployment during scheduled maintenance to minimize business disruption.
- Use Case: Protects against vulnerabilities that adversaries could exploit to gain access to network devices or inject malicious traffic.

Emergency Patch Deployment

- Implementation: Use the emergency patch deployment feature of the organization's patch management tool to apply updates to all affected Exchange servers within 24 hours.
- Use Case: Reduces the risk of exploitation by rapidly addressing critical vulnerabilities.

Centralized Patch Management

- Implementation: Implement a centralized patch management system, such as SCCM or ManageEngine, to automate and track patch deployment across all environments. Generate regular compliance reports to ensure all systems are updated.
- Use Case: Streamlines patching processes and ensures no critical systems are missed.

*Tools for Implementation*

Patch Management Tools:

- WSUS: Manage and deploy Microsoft updates across the organization.
- ManageEngine Patch Manager Plus: Automate patch deployment for OS and third-party apps.
- Ansible: Automate updates across multiple platforms, including Linux and Windows.

Vulnerability Scanning Tools:

- OpenVAS: Open-source vulnerability scanning to identify missing patches.

### Sub: user_account_control [T1550.002]
**M1052 — User Account Control**

User Account Control (UAC) is a security feature in Microsoft Windows that prevents unauthorized changes to the operating system. UAC prompts users to confirm or provide administrator credentials when an action requires elevated privileges. Proper configuration of UAC reduces the risk of privilege escalation attacks. This mitigation can be implemented through the following measures:

Enable UAC Globally:

- Ensure UAC is enabled through Group Policy by setting `User Account Control: Run all administrators in Admin Approval Mode` to `Enabled`.

Require Credential Prompt:

- Use Group Policy to configure UAC to prompt for administrative credentials instead of just confirmation (`User Account Control: Behavior of the elevation prompt`).

Restrict Built-in Administrator Account:

Set `Admin Approval Mode` for the built-in Administrator account to `Enabled` in Group Policy.

Secure the UAC Prompt:

- Configure UAC prompts to display on the secure desktop (`User Account Control: Switch to the secure desktop when prompting for elevation`).

Prevent UAC Bypass:

- Block untrusted applications from triggering UAC prompts by configuring `User Account Control: Only elevate executables that are signed and validated`.
- Use EDR tools to detect and block known UAC bypass techniques.

Monitor UAC-Related Events:

- Use Windows Event Viewer to monitor for event ID 4688 (process creation) and look for suspicious processes attempting to invoke UAC elevation.

*Tools for Implementation*

Built-in Windows Tools:

- Group Policy Editor: Configure UAC settings centrally for enterprise environments.
- Registry Editor: Modify UAC-related settings directly, such as `EnableLUA` and `ConsentPromptBehaviorAdmin`.

Endpoint Security Solutions:

- Microsoft Defender for Endpoint: Detects and blocks UAC bypass techniques.
- Sysmon: Logs process creations and monitors UAC elevation attempts for suspicious activity.

Third-Party Security Tools:

- Process Monitor (Sysinternals): Tracks real-time processes interacting with UAC.
- EventSentry: Monitors Windows Event Logs for UAC-related alerts.

### Sub: user_account_management [T1550.002]
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

### Sub: privileged_account_management [T1550.002]
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
