---
threat_name: Brute Force
technique_ids: ["T1110.001", "T1110.003", "T1078"]
severity: Medium
source_doc: Brute_Force_IR_Playbook_v1
---

## เอกสารอ้างอิง — Preparation, Detection & Post-Incident Review (ไม่ถูก ingest เป็น RAG chunk)

> ขอบเขต proposal §3.3 กำหนดให้ playbook เชิงรับมีแค่ 3 phase: Containment / Eradication / Recovery
> เนื้อหา Preparation กับ Detection เดิมยังมีคุณค่าอยู่ (ทีมเขียนเอง) จึงเก็บไว้เป็นเอกสารอ้างอิงตรงนี้แทน
> ไม่ได้อยู่ใต้ `## Phase:` จึงไม่ถูก `01_ingest.py` ดึงเข้า ChromaDB — อ่านเป็นบริบทประกอบเท่านั้น
> (ส่วน detection signal เช่น log source/IOC list เหมาะเอาไปใช้ต่อตอน implement CTI enrichment
> หรือ NCSC severity assessment ในอนาคต ไม่ใช่ทิ้งไปเฉยๆ)

**Tool readiness:** เตรียม fail2ban / Windows Account Lockout Policy (lockout หลัง 5 ครั้ง), Hydra/Medusa บน sandbox สำหรับทดสอบ detection, GoAccess หรือ script parse auth log, access ไปยัง Active Directory Audit Log (Event ID 4625, 4740, 4771), GeoIP lookup tool (MaxMind GeoLite2), Duo/Azure AD MFA สำหรับ remediation ฉุกเฉิน, password reset workflow ที่ผ่าน out-of-band verification

**Team roles:** Incident Commander (ตัดสินใจ lockout/block IP ระดับ network), SOC Analyst L2 (monitor auth log real-time), AD Admin (reset password/unlock/ตรวจ group membership), Network Engineer (block source IP), Application Owner (ตรวจ login log), Help Desk (verify identity ก่อน unlock)

**Comm plan:** แจ้ง AD Admin ทันทีเมื่อ lockout > 10 accounts, ส่ง P2 Alert ไปยัง CISO ถ้า admin account ถูก target, ใช้ secure channel แจ้ง reset password, แจ้ง ISP ถ้าเจอ botnet IP ขนาดใหญ่, ประสาน HR ถ้า executive account ถูก target

**Log sources:** Windows Security Event Log (4625 logon failure, 4740 account lockout, 4771 Kerberos pre-auth failure), Linux auth log (`/var/log/auth.log`, `/var/log/secure`), Web Application Log (HTTP 401/403 ซ้ำจาก IP เดียว), VPN Access Log, RADIUS Log, Azure AD/Entra ID Sign-in Log (สำหรับ spraying), Microsoft 365 Unified Audit Log

**IoC list:** High failure rate (>50 ครั้ง/5 นาทีต่อ IP), sequential username pattern (admin, administrator, admin1...), non-business hour activity, Tor exit node/VPN IP, Logon Type 3 จาก IP ใหม่, Kerberos Error 0x18 (guessing) / password spray pattern เดียวกระจายหลายบัญชี, low-and-slow timing (spraying)

**Lessons learned (ทำหลังปิดเคส):** เช็คว่า Lockout Policy มีอยู่แล้วหรือไม่และทำไมไม่ block ทัน, MFA ถูก enforce กับบัญชีที่ถูก target หรือไม่, ประเมิน MTTD ว่า SIEM alert เร็วพอไหม, ผลกระทบต่อ business operations, มี password reuse ข้ามระบบหรือไม่

**Improvements ที่ควรผลักดันต่อ:** บังคับ MFA ทุกบัญชีโดยเฉพาะ privileged ภายใน 30 วัน, เพิ่ม SIEM rule ตรวจ password spray pattern, deploy Identity Protection, ทำ Privileged Access Workstation (PAW), จัด training เรื่อง password manager

## Phase: containment
### Sub: short_term
1. **Lock account ที่ถูก target** ชั่วคราวจาก AD: `Disable-ADAccount -Identity <username>`
2. **Block source IP** ที่ Firewall ทันที: `netsh advfirewall firewall add rule name="Block Brute Force" dir=in action=block remoteip=<attacker_ip>`
3. **เปิด fail2ban** สำหรับ SSH บน Linux หากยังไม่ได้เปิด: `systemctl enable --now fail2ban`
4. **บังคับ CAPTCHA** ที่ login page สำหรับ IP ที่มี failure > 5 ครั้ง
5. **Reset password** ทันทีสำหรับ account ที่มี Event ID 4624 (successful login) หลังถูก brute force
6. **Revoke active session** สำหรับ account ที่สงสัยถูก compromise
7. **เปิด MFA ฉุกเฉิน** สำหรับ privileged account ทุก account ที่ยังไม่มี MFA

### Sub: long_term
- บังคับใช้ **Account Lockout Policy**: lockout หลัง 5 failures, reset counter ทุก 30 นาที
- Deploy **MFA สำหรับ remote access ทุก protocol** (VPN, RDP, OWA, SSH)
- ใช้ **Geo-blocking**: block ประเทศที่ไม่มี business relationship
- Implement **Adaptive Authentication**: เพิ่ม friction เมื่อ login จาก IP/device ใหม่
- ติดตั้ง **Honeypot account** (เช่น account ชื่อ "admin" ที่ไม่ได้ใช้จริง) สำหรับ early warning

### Sub: evidence_preservation
- Export **Windows Security Event Log** ทั้งหมด ช่วง incident: `wevtutil epl Security C:\evidence\security_log.evtx`
- เก็บ **auth.log** บน Linux: `cp /var/log/auth.log /evidence/auth.log && sha256sum /evidence/auth.log`
- บันทึก **IP list ที่เกี่ยวข้อง** พร้อม timestamp และ GeoIP ลงใน CSV
- เก็บ **AD audit log** โดยเฉพาะ Event 4625, 4740, 4624 ช่วง incident
- Screenshot **SIEM dashboard** ที่แสดง attack pattern

## Phase: eradication
### Sub: process_removal
- ยืนยันว่าไม่มี **backdoor process** ที่ถูกสร้างหลัง successful login:
  ```powershell
  Get-Process | Where-Object {$_.StartTime -gt (Get-Date).AddHours(-24)} | Select-Object Name, Id, StartTime, Path
  ```
- ตรวจสอบ **scheduled task** ที่สร้างโดย account ที่ถูก compromise:
  ```powershell
  Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "<compromised_user>"}
  ```
- ตรวจสอบ **new local user** ที่ถูกสร้างหลัง brute force สำเร็จ: `net user` และ `Get-LocalUser`

### Sub: persistence_removal
- **Reset password** ทุก account ที่ถูก brute force สำเร็จ และ force password change at next logon
- ลบ **SSH authorized_keys** ที่ถูกเพิ่มโดย attacker: `cat ~/.ssh/authorized_keys` และลบ key ที่ไม่รู้จัก
- ตรวจสอบ **sudoers file** บน Linux: `cat /etc/sudoers` และ `/etc/sudoers.d/`
- ลบ **registry Run key** ที่ถูกเพิ่มโดย account ที่ถูก compromise:
  ```powershell
  Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
  ```

### Sub: patching
- **อัปเดต Account Lockout Policy** ผ่าน Group Policy: Computer Configuration → Windows Settings → Security Settings → Account Policies
- ติดตั้ง **MFA solution** สำหรับ all remote access: Azure AD MFA, Duo, Google Authenticator
- อัปเดต **SSH configuration**: ปิด `PasswordAuthentication no`, ใช้ key-based auth เท่านั้น
- ทบทวน **password complexity policy**: minimum 14 characters, check against HaveIBeenPwned wordlist

## Phase: recovery
### Sub: service_restoration
- **Unlock account** เฉพาะหลัง verify identity เจ้าของบัญชีผ่านช่องทาง out-of-band (โทรศัพท์/ต่อหน้า) ไม่ใช่ตาม request ทาง email/chat เพียงอย่างเดียว
- **คืนสิทธิ์ทีละขั้น**: เปิด MFA ให้บัญชีที่ถูก target ก่อน แล้วค่อย unlock ไม่ปลด lockout ก่อนมี MFA
- ทยอย **ผ่อนคลาย geo-block/CAPTCHA ชั่วคราว** ที่เปิดไว้ตอน containment กลับสู่ policy ปกติ เมื่อยืนยันว่าการโจมตีหยุดแล้วอย่างน้อย 24–48 ชั่วโมง
- แจ้ง **Application Owner / Help Desk** ว่าบัญชีกลับมาใช้งานได้แล้ว พร้อมสรุปเงื่อนไขที่เปลี่ยน (เช่น ต้องใช้ MFA ทุกครั้ง)

### Sub: validation_monitoring
- ตรวจสอบว่าไม่มี **session ค้าง** หรือ token เก่าที่ยังใช้ได้หลัง reset password (`klist purge`, revoke refresh token บน cloud identity)
- เฝ้าระวัง **Event ID 4625/4740 ซ้ำ** จาก IP หรือบัญชีเดิมต่ออีกอย่างน้อย 7 วัน ก่อนปิดเคส
- ยืนยันว่า **MFA enrollment** ของบัญชีที่ถูก target สำเร็จจริง (ทดสอบ login จริงหนึ่งรอบ)
- เทียบ **baseline การล็อกอิน** ของบัญชีก่อน/หลังเหตุการณ์ว่ากลับสู่ภาวะปกติ

### Sub: closure
- บันทึก **สรุปเหตุการณ์และเงื่อนไขการปิดเคส** ลง incident ticket (เวลาเริ่ม/จบ, บัญชี/IP ที่เกี่ยวข้อง, มาตรการที่คงไว้ถาวร)
- ยืนยันกับ **Application Owner** ว่า business operations กลับมาปกติ ไม่มี ticket ค้างจากผู้ใช้ที่ถูกกระทบ
- ส่งต่อรายการ **มาตรการระยะยาวที่ยังไม่เสร็จ** (เช่น MFA ทุก account, geo-blocking ถาวร) เป็น follow-up item ไม่ใช่ปิดเงียบ
