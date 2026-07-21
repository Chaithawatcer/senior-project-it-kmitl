---
threat_name: "Valid Accounts"
technique_ids: ["T1078"]
severity: Medium
source_doc: "MITRE_ATTACK_Mitigations_T1078"
doc_type: mitre
---

> ที่มา: MITRE ATT&CK (T1078 — Valid Accounts) ดึงผ่าน mitreattack-python (offline)
> เนื้อหาด้านล่างคือคำอธิบายทางการจาก ATT&CK โดยตรง ไม่ได้เรียบเรียงใหม่
> เพื่อให้อ้างอิงย้อนกลับไปยังเอกสารต้นฉบับได้ตรง

## Phase: containment
### Sub: password_policies [T1078]
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

### Sub: user_account_management [T1078]
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

### Sub: privileged_account_management [T1078]
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

### Sub: multi-factor_authentication [T1078]
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

### Sub: application_developer_guidance [T1078]
**M1013 — Application Developer Guidance**

Application Developer Guidance focuses on providing developers with the knowledge, tools, and best practices needed to write secure code, reduce vulnerabilities, and implement secure design principles. By integrating security throughout the software development lifecycle (SDLC), this mitigation aims to prevent the introduction of exploitable weaknesses in applications, systems, and APIs. This mitigation can be implemented through the following measures:
 
Preventing SQL Injection (Secure Coding Practice):

- Implementation: Train developers to use parameterized queries or prepared statements instead of directly embedding user input into SQL queries.
- Use Case: A web application accepts user input to search a database. By sanitizing and validating user inputs, developers can prevent attackers from injecting malicious SQL commands.

Cross-Site Scripting (XSS) Mitigation:

- Implementation: Require developers to implement output encoding for all user-generated content displayed on a web page.
- Use Case: An e-commerce site allows users to leave product reviews. Properly encoding and escaping user inputs prevents malicious scripts from being executed in other users’ browsers.

Secure API Design:

- Implementation: Train developers to authenticate all API endpoints and avoid exposing sensitive information in API responses.
- Use Case: A mobile banking application uses APIs for account management. By enforcing token-based authentication for every API call, developers reduce the risk of unauthorized access.

Static Code Analysis in the Build Pipeline:

- Implementation: Incorporate tools into CI/CD pipelines to automatically scan for vulnerabilities during the build process.
- Use Case: A fintech company integrates static analysis tools to detect hardcoded credentials in their source code before deployment.

Threat Modeling in the Design Phase:

- Implementation: Use frameworks like STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to assess threats during application design.
- Use Case: Before launching a customer portal, a SaaS company identifies potential abuse cases, such as session hijacking, and designs mitigations like secure session management.

**Tools for Implementation**:

- Static Code Analysis Tools: Use tools that can scan for known vulnerabilities in source code.
- Dynamic Application Security Testing (DAST): Use tools like Burp Suite or OWASP ZAP to simulate runtime attacks and identify vulnerabilities.
- Secure Frameworks: Recommend secure-by-default frameworks (e.g., Django for Python, Spring Security for Java) that enforce security best practices.

### Sub: user_training [T1078]
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

### Sub: active_directory_configuration [T1078]
**M1015 — Active Directory Configuration**

Implement robust Active Directory (AD) configurations using group policies to secure user accounts, control access, and minimize the attack surface. AD configurations enable centralized control over account settings, logon policies, and permissions, reducing the risk of unauthorized access and lateral movement within the network. This mitigation can be implemented through the following measures:

Account Configuration:

- Implementation: Use domain accounts instead of local accounts to leverage AD’s centralized management, including group policies, auditing, and access control.
- Use Case: For IT staff managing shared resources, provision domain accounts that allow IT teams to log in centrally, reducing the risk of unmanaged, rogue local accounts on individual machines.

Interactive Logon Restrictions:

- Implementation: Configure group policies to restrict interactive logons (e.g., direct physical or RDP logons) for service accounts or privileged accounts that do not require such access.
- Use Case: Prevent service accounts, such as SQL Server accounts, from having interactive logon privileges. This reduces the risk of these accounts being leveraged for lateral movement if compromised.

Remote Desktop Settings:

- Implementation: Limit Remote Desktop Protocol (RDP) access to specific, authorized accounts. Use group policies to enforce this, allowing only necessary users to establish RDP sessions.
- Use Case: On sensitive servers (e.g., domain controllers or financial databases), restrict RDP access to administrative accounts only, while all other users are denied access.

Dedicated Administrative Accounts:

- Implementation: Create domain-wide administrative accounts that are restricted from interactive logons, designed solely for high-level tasks (e.g., software installation, patching).
- Use Case: Create separate administrative accounts for different purposes, such as one set of accounts for installations and another for managing repository access. This limits exposure and helps reduce attack vectors.

Authentication Silos:

- Implementation: Configure Authentication Silos in AD, using group policies to create access zones with restrictions based on membership, such as the Protected Users security group. This restricts access to critical accounts and minimizes exposure to potential threats.
- Use Case: Place high-risk or high-value accounts, such as executive or administrative accounts, in an Authentication Silo with extra controls, limiting their exposure to only necessary systems. This reduces the risk of credential misuse or abuse if these accounts are compromised.

**Tools for Implementation**:

- Active Directory Group Policies: Use Group Policy Management Console (GPMC) to configure, deploy, and enforce policies across AD environments.
- PowerShell: Automate account configuration, logon restrictions, and policy application using PowerShell scripts.
- AD Administrative Center: Manage Authentication Silos and configure high-level policies for critical user groups within AD.

### Sub: account_use_policies [T1078]
**M1036 — Account Use Policies**

Account Use Policies help mitigate unauthorized access by configuring and enforcing rules that govern how and when accounts can be used. These policies include enforcing account lockout mechanisms, restricting login times, and setting inactivity timeouts. Proper configuration of these policies reduces the risk of brute-force attacks, credential theft, and unauthorized access by limiting the opportunities for malicious actors to exploit accounts. This mitigation can be implemented through the following measures:

Account Lockout Policies:

- Implementation: Configure account lockout settings so that after a defined number of failed login attempts (e.g., 3-5 attempts), the account is locked for a specific time period (e.g., 15 minutes) or requires an administrator to unlock it.
- Use Case: This prevents brute-force attacks by limiting how many incorrect password attempts can be made before the account is temporarily disabled, reducing the likelihood of an attacker successfully guessing a password.

Login Time Restrictions:

- Implementation: Set up login time policies to restrict when users or groups can log into systems. For example, only allowing login during standard business hours (e.g., 8 AM to 6 PM) for non-administrative accounts.
- Use Case: This prevents unauthorized access outside of approved working hours, where login attempts might be more suspicious or harder to monitor. For example, if an account that is only supposed to be active during the day logs in at 2 AM, it should raise an alert or be blocked.

Inactivity Timeout and Session Termination:

- Implementation: Enforce session timeouts after a period of inactivity (e.g., 10-15 minutes) and require users to re-authenticate if they wish to resume the session.
- Use Case: This policy prevents attackers from hijacking active sessions left unattended. For example, if an employee walks away from their computer without locking it, an attacker with physical access to the system would be unable to exploit the session.

Password Aging Policies:

- Implementation: Enforce password aging rules, requiring users to change their passwords after a defined period (e.g., 90 days) and ensure passwords are not reused by maintaining a password history.
- Use Case: This limits the risk of compromised passwords being used indefinitely. Regular password changes make it more difficult for attackers to reuse stolen credentials.

Account Expiration and Deactivation:

- Implementation: Configure user accounts, especially for temporary or contract workers, to automatically expire after a set date or event. Accounts that remain unused for a specific period should be deactivated automatically.
- Use Case: This prevents dormant accounts from becoming an attack vector. For example, an attacker can exploit unused accounts if they are not properly monitored or deactivated.

**Tools for Implementation**:

- Group Policy Objects (GPOs) in Windows: To enforce account lockout thresholds, login time restrictions, session timeouts, and password policies.
- Identity and Access Management (IAM) solutions: For centralized management of user accounts, session policies, and automated deactivation of accounts.
- Security Information and Event Management (SIEM) platforms: To monitor and alert on unusual login activity, such as failed logins or out-of-hours access attempts.
- Multi-Factor Authentication (MFA) Tools: To further enforce secure login attempts, preventing brute-force or credential stuffing attacks.

## Phase: eradication
### Sub: password_policies [T1078]
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

### Sub: user_account_management [T1078]
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

### Sub: privileged_account_management [T1078]
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

### Sub: multi-factor_authentication [T1078]
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

### Sub: application_developer_guidance [T1078]
**M1013 — Application Developer Guidance**

Application Developer Guidance focuses on providing developers with the knowledge, tools, and best practices needed to write secure code, reduce vulnerabilities, and implement secure design principles. By integrating security throughout the software development lifecycle (SDLC), this mitigation aims to prevent the introduction of exploitable weaknesses in applications, systems, and APIs. This mitigation can be implemented through the following measures:
 
Preventing SQL Injection (Secure Coding Practice):

- Implementation: Train developers to use parameterized queries or prepared statements instead of directly embedding user input into SQL queries.
- Use Case: A web application accepts user input to search a database. By sanitizing and validating user inputs, developers can prevent attackers from injecting malicious SQL commands.

Cross-Site Scripting (XSS) Mitigation:

- Implementation: Require developers to implement output encoding for all user-generated content displayed on a web page.
- Use Case: An e-commerce site allows users to leave product reviews. Properly encoding and escaping user inputs prevents malicious scripts from being executed in other users’ browsers.

Secure API Design:

- Implementation: Train developers to authenticate all API endpoints and avoid exposing sensitive information in API responses.
- Use Case: A mobile banking application uses APIs for account management. By enforcing token-based authentication for every API call, developers reduce the risk of unauthorized access.

Static Code Analysis in the Build Pipeline:

- Implementation: Incorporate tools into CI/CD pipelines to automatically scan for vulnerabilities during the build process.
- Use Case: A fintech company integrates static analysis tools to detect hardcoded credentials in their source code before deployment.

Threat Modeling in the Design Phase:

- Implementation: Use frameworks like STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to assess threats during application design.
- Use Case: Before launching a customer portal, a SaaS company identifies potential abuse cases, such as session hijacking, and designs mitigations like secure session management.

**Tools for Implementation**:

- Static Code Analysis Tools: Use tools that can scan for known vulnerabilities in source code.
- Dynamic Application Security Testing (DAST): Use tools like Burp Suite or OWASP ZAP to simulate runtime attacks and identify vulnerabilities.
- Secure Frameworks: Recommend secure-by-default frameworks (e.g., Django for Python, Spring Security for Java) that enforce security best practices.

### Sub: user_training [T1078]
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

### Sub: active_directory_configuration [T1078]
**M1015 — Active Directory Configuration**

Implement robust Active Directory (AD) configurations using group policies to secure user accounts, control access, and minimize the attack surface. AD configurations enable centralized control over account settings, logon policies, and permissions, reducing the risk of unauthorized access and lateral movement within the network. This mitigation can be implemented through the following measures:

Account Configuration:

- Implementation: Use domain accounts instead of local accounts to leverage AD’s centralized management, including group policies, auditing, and access control.
- Use Case: For IT staff managing shared resources, provision domain accounts that allow IT teams to log in centrally, reducing the risk of unmanaged, rogue local accounts on individual machines.

Interactive Logon Restrictions:

- Implementation: Configure group policies to restrict interactive logons (e.g., direct physical or RDP logons) for service accounts or privileged accounts that do not require such access.
- Use Case: Prevent service accounts, such as SQL Server accounts, from having interactive logon privileges. This reduces the risk of these accounts being leveraged for lateral movement if compromised.

Remote Desktop Settings:

- Implementation: Limit Remote Desktop Protocol (RDP) access to specific, authorized accounts. Use group policies to enforce this, allowing only necessary users to establish RDP sessions.
- Use Case: On sensitive servers (e.g., domain controllers or financial databases), restrict RDP access to administrative accounts only, while all other users are denied access.

Dedicated Administrative Accounts:

- Implementation: Create domain-wide administrative accounts that are restricted from interactive logons, designed solely for high-level tasks (e.g., software installation, patching).
- Use Case: Create separate administrative accounts for different purposes, such as one set of accounts for installations and another for managing repository access. This limits exposure and helps reduce attack vectors.

Authentication Silos:

- Implementation: Configure Authentication Silos in AD, using group policies to create access zones with restrictions based on membership, such as the Protected Users security group. This restricts access to critical accounts and minimizes exposure to potential threats.
- Use Case: Place high-risk or high-value accounts, such as executive or administrative accounts, in an Authentication Silo with extra controls, limiting their exposure to only necessary systems. This reduces the risk of credential misuse or abuse if these accounts are compromised.

**Tools for Implementation**:

- Active Directory Group Policies: Use Group Policy Management Console (GPMC) to configure, deploy, and enforce policies across AD environments.
- PowerShell: Automate account configuration, logon restrictions, and policy application using PowerShell scripts.
- AD Administrative Center: Manage Authentication Silos and configure high-level policies for critical user groups within AD.

### Sub: account_use_policies [T1078]
**M1036 — Account Use Policies**

Account Use Policies help mitigate unauthorized access by configuring and enforcing rules that govern how and when accounts can be used. These policies include enforcing account lockout mechanisms, restricting login times, and setting inactivity timeouts. Proper configuration of these policies reduces the risk of brute-force attacks, credential theft, and unauthorized access by limiting the opportunities for malicious actors to exploit accounts. This mitigation can be implemented through the following measures:

Account Lockout Policies:

- Implementation: Configure account lockout settings so that after a defined number of failed login attempts (e.g., 3-5 attempts), the account is locked for a specific time period (e.g., 15 minutes) or requires an administrator to unlock it.
- Use Case: This prevents brute-force attacks by limiting how many incorrect password attempts can be made before the account is temporarily disabled, reducing the likelihood of an attacker successfully guessing a password.

Login Time Restrictions:

- Implementation: Set up login time policies to restrict when users or groups can log into systems. For example, only allowing login during standard business hours (e.g., 8 AM to 6 PM) for non-administrative accounts.
- Use Case: This prevents unauthorized access outside of approved working hours, where login attempts might be more suspicious or harder to monitor. For example, if an account that is only supposed to be active during the day logs in at 2 AM, it should raise an alert or be blocked.

Inactivity Timeout and Session Termination:

- Implementation: Enforce session timeouts after a period of inactivity (e.g., 10-15 minutes) and require users to re-authenticate if they wish to resume the session.
- Use Case: This policy prevents attackers from hijacking active sessions left unattended. For example, if an employee walks away from their computer without locking it, an attacker with physical access to the system would be unable to exploit the session.

Password Aging Policies:

- Implementation: Enforce password aging rules, requiring users to change their passwords after a defined period (e.g., 90 days) and ensure passwords are not reused by maintaining a password history.
- Use Case: This limits the risk of compromised passwords being used indefinitely. Regular password changes make it more difficult for attackers to reuse stolen credentials.

Account Expiration and Deactivation:

- Implementation: Configure user accounts, especially for temporary or contract workers, to automatically expire after a set date or event. Accounts that remain unused for a specific period should be deactivated automatically.
- Use Case: This prevents dormant accounts from becoming an attack vector. For example, an attacker can exploit unused accounts if they are not properly monitored or deactivated.

**Tools for Implementation**:

- Group Policy Objects (GPOs) in Windows: To enforce account lockout thresholds, login time restrictions, session timeouts, and password policies.
- Identity and Access Management (IAM) solutions: For centralized management of user accounts, session policies, and automated deactivation of accounts.
- Security Information and Event Management (SIEM) platforms: To monitor and alert on unusual login activity, such as failed logins or out-of-hours access attempts.
- Multi-Factor Authentication (MFA) Tools: To further enforce secure login attempts, preventing brute-force or credential stuffing attacks.

## Phase: recovery
### Sub: password_policies [T1078]
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

### Sub: user_account_management [T1078]
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

### Sub: privileged_account_management [T1078]
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

### Sub: multi-factor_authentication [T1078]
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

### Sub: application_developer_guidance [T1078]
**M1013 — Application Developer Guidance**

Application Developer Guidance focuses on providing developers with the knowledge, tools, and best practices needed to write secure code, reduce vulnerabilities, and implement secure design principles. By integrating security throughout the software development lifecycle (SDLC), this mitigation aims to prevent the introduction of exploitable weaknesses in applications, systems, and APIs. This mitigation can be implemented through the following measures:
 
Preventing SQL Injection (Secure Coding Practice):

- Implementation: Train developers to use parameterized queries or prepared statements instead of directly embedding user input into SQL queries.
- Use Case: A web application accepts user input to search a database. By sanitizing and validating user inputs, developers can prevent attackers from injecting malicious SQL commands.

Cross-Site Scripting (XSS) Mitigation:

- Implementation: Require developers to implement output encoding for all user-generated content displayed on a web page.
- Use Case: An e-commerce site allows users to leave product reviews. Properly encoding and escaping user inputs prevents malicious scripts from being executed in other users’ browsers.

Secure API Design:

- Implementation: Train developers to authenticate all API endpoints and avoid exposing sensitive information in API responses.
- Use Case: A mobile banking application uses APIs for account management. By enforcing token-based authentication for every API call, developers reduce the risk of unauthorized access.

Static Code Analysis in the Build Pipeline:

- Implementation: Incorporate tools into CI/CD pipelines to automatically scan for vulnerabilities during the build process.
- Use Case: A fintech company integrates static analysis tools to detect hardcoded credentials in their source code before deployment.

Threat Modeling in the Design Phase:

- Implementation: Use frameworks like STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to assess threats during application design.
- Use Case: Before launching a customer portal, a SaaS company identifies potential abuse cases, such as session hijacking, and designs mitigations like secure session management.

**Tools for Implementation**:

- Static Code Analysis Tools: Use tools that can scan for known vulnerabilities in source code.
- Dynamic Application Security Testing (DAST): Use tools like Burp Suite or OWASP ZAP to simulate runtime attacks and identify vulnerabilities.
- Secure Frameworks: Recommend secure-by-default frameworks (e.g., Django for Python, Spring Security for Java) that enforce security best practices.

### Sub: user_training [T1078]
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

### Sub: active_directory_configuration [T1078]
**M1015 — Active Directory Configuration**

Implement robust Active Directory (AD) configurations using group policies to secure user accounts, control access, and minimize the attack surface. AD configurations enable centralized control over account settings, logon policies, and permissions, reducing the risk of unauthorized access and lateral movement within the network. This mitigation can be implemented through the following measures:

Account Configuration:

- Implementation: Use domain accounts instead of local accounts to leverage AD’s centralized management, including group policies, auditing, and access control.
- Use Case: For IT staff managing shared resources, provision domain accounts that allow IT teams to log in centrally, reducing the risk of unmanaged, rogue local accounts on individual machines.

Interactive Logon Restrictions:

- Implementation: Configure group policies to restrict interactive logons (e.g., direct physical or RDP logons) for service accounts or privileged accounts that do not require such access.
- Use Case: Prevent service accounts, such as SQL Server accounts, from having interactive logon privileges. This reduces the risk of these accounts being leveraged for lateral movement if compromised.

Remote Desktop Settings:

- Implementation: Limit Remote Desktop Protocol (RDP) access to specific, authorized accounts. Use group policies to enforce this, allowing only necessary users to establish RDP sessions.
- Use Case: On sensitive servers (e.g., domain controllers or financial databases), restrict RDP access to administrative accounts only, while all other users are denied access.

Dedicated Administrative Accounts:

- Implementation: Create domain-wide administrative accounts that are restricted from interactive logons, designed solely for high-level tasks (e.g., software installation, patching).
- Use Case: Create separate administrative accounts for different purposes, such as one set of accounts for installations and another for managing repository access. This limits exposure and helps reduce attack vectors.

Authentication Silos:

- Implementation: Configure Authentication Silos in AD, using group policies to create access zones with restrictions based on membership, such as the Protected Users security group. This restricts access to critical accounts and minimizes exposure to potential threats.
- Use Case: Place high-risk or high-value accounts, such as executive or administrative accounts, in an Authentication Silo with extra controls, limiting their exposure to only necessary systems. This reduces the risk of credential misuse or abuse if these accounts are compromised.

**Tools for Implementation**:

- Active Directory Group Policies: Use Group Policy Management Console (GPMC) to configure, deploy, and enforce policies across AD environments.
- PowerShell: Automate account configuration, logon restrictions, and policy application using PowerShell scripts.
- AD Administrative Center: Manage Authentication Silos and configure high-level policies for critical user groups within AD.

### Sub: account_use_policies [T1078]
**M1036 — Account Use Policies**

Account Use Policies help mitigate unauthorized access by configuring and enforcing rules that govern how and when accounts can be used. These policies include enforcing account lockout mechanisms, restricting login times, and setting inactivity timeouts. Proper configuration of these policies reduces the risk of brute-force attacks, credential theft, and unauthorized access by limiting the opportunities for malicious actors to exploit accounts. This mitigation can be implemented through the following measures:

Account Lockout Policies:

- Implementation: Configure account lockout settings so that after a defined number of failed login attempts (e.g., 3-5 attempts), the account is locked for a specific time period (e.g., 15 minutes) or requires an administrator to unlock it.
- Use Case: This prevents brute-force attacks by limiting how many incorrect password attempts can be made before the account is temporarily disabled, reducing the likelihood of an attacker successfully guessing a password.

Login Time Restrictions:

- Implementation: Set up login time policies to restrict when users or groups can log into systems. For example, only allowing login during standard business hours (e.g., 8 AM to 6 PM) for non-administrative accounts.
- Use Case: This prevents unauthorized access outside of approved working hours, where login attempts might be more suspicious or harder to monitor. For example, if an account that is only supposed to be active during the day logs in at 2 AM, it should raise an alert or be blocked.

Inactivity Timeout and Session Termination:

- Implementation: Enforce session timeouts after a period of inactivity (e.g., 10-15 minutes) and require users to re-authenticate if they wish to resume the session.
- Use Case: This policy prevents attackers from hijacking active sessions left unattended. For example, if an employee walks away from their computer without locking it, an attacker with physical access to the system would be unable to exploit the session.

Password Aging Policies:

- Implementation: Enforce password aging rules, requiring users to change their passwords after a defined period (e.g., 90 days) and ensure passwords are not reused by maintaining a password history.
- Use Case: This limits the risk of compromised passwords being used indefinitely. Regular password changes make it more difficult for attackers to reuse stolen credentials.

Account Expiration and Deactivation:

- Implementation: Configure user accounts, especially for temporary or contract workers, to automatically expire after a set date or event. Accounts that remain unused for a specific period should be deactivated automatically.
- Use Case: This prevents dormant accounts from becoming an attack vector. For example, an attacker can exploit unused accounts if they are not properly monitored or deactivated.

**Tools for Implementation**:

- Group Policy Objects (GPOs) in Windows: To enforce account lockout thresholds, login time restrictions, session timeouts, and password policies.
- Identity and Access Management (IAM) solutions: For centralized management of user accounts, session policies, and automated deactivation of accounts.
- Security Information and Event Management (SIEM) platforms: To monitor and alert on unusual login activity, such as failed logins or out-of-hours access attempts.
- Multi-Factor Authentication (MFA) Tools: To further enforce secure login attempts, preventing brute-force or credential stuffing attacks.
