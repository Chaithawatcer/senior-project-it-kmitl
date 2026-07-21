---
threat_name: RDP Brute Force
technique_ids: ["T1110.001", "T1021.001", "T1078"]
severity: High
source_doc: RDP_Brute_Force_IR_Playbook_v1
---

## Phase: preparation
### Sub: tool_readiness
- เปิด **Windows Security Audit Policy** สำหรับ Event ID 4625 (logon failure), 4624 (logon success), 4778 (session reconnect)
- ติดตั้ง **RDPGuard** หรือ **fail2ban สำหรับ Windows** สำหรับ auto-block IP หลัง failed login
- เตรียม **NLA (Network Level Authentication)** เพื่อบังคับ authentication ก่อน establish RDP session
- มี **GeoIP database** สำหรับ ระบุประเทศของ source IP ที่ brute force
- เตรียม **Shodan/Censys lookup** สำหรับ ตรวจว่า RDP port ถูก expose บน internet หรือไม่
- ติดตั้ง **Sysmon** สำหรับ log process ที่ spawn หลัง RDP login สำเร็จ
- เตรียม list ของ **Tor exit node IP** และ **commercial VPN IP range** สำหรับ threat intel

### Sub: team_roles
- **Incident Commander**: ตัดสินใจ block RDP จาก internet ทันที vs ปล่อยไว้เพื่อ monitor
- **Windows/AD Admin**: ตรวจสอบ account lockout, reset password, ตรวจสอบ RDP session ที่ active
- **Network Engineer**: block source IP ที่ Firewall, ตรวจสอบว่า RDP expose โดยตรงจาก internet
- **SOC Analyst (L2/L3)**: monitor Event 4625/4624 แบบ real-time, ระบุ pattern และ target account
- **Forensic Analyst**: เก็บ evidence จาก RDP session ที่สำเร็จ — ตรวจว่า attacker ทำอะไรบ้าง
- **Help Desk**: รับแจ้ง user ที่ถูก lockout และ verify identity ก่อน unlock

### Sub: comm_plan
- แจ้ง **Windows Admin** ทันทีเมื่อพบ Event 4625 > 50 ครั้งจาก IP เดียวใน 5 นาที
- ส่ง **P1 Alert** ทันทีหากพบ Event 4624 Type 10 (RDP successful login) จาก IP ต่างประเทศ
- แจ้ง **Network team** เพื่อ block IP และ evaluate ว่า RDP ควร expose ผ่าน internet โดยตรงหรือไม่
- ประสาน **application owner** สำหรับ server ที่ถูก RDP brute force เพื่อ assess business impact
- บันทึก **IP list, account target, timestamp** ใน incident ticket ทุก update

## Phase: detection
### Sub: log_sources
- **Windows Security Event ID 4625**: Failed logon — บันทึก Logon Type, source IP, target account, failure reason
- **Windows Security Event ID 4624 Type 10**: Successful RemoteInteractive logon — RDP login สำเร็จ
- **Windows Security Event ID 4778**: Remote session reconnected — RDP session กลับมา reconnect
- **Windows Security Event ID 4740**: Account lockout เนื่องจาก repeated failure
- **TerminalServices-RemoteConnectionManager Log**: Event ID 1149 — Remote Desktop Services: User authentication succeeded/failed
- **TerminalServices-LocalSessionManager Log**: Event ID 21 (session logon), 23 (logoff), 24 (disconnect)
- **Sysmon Event ID 1**: process ที่ spawn ใน session ที่ login ผ่าน RDP (Type 10)
- **Firewall Log**: inbound connection บน port 3389 จาก IP ที่ผิดปกติ

### Sub: ioc_list
- **Event ID 4625 Type 10**: > 20 ครั้งใน 5 นาทีจาก IP เดียว ไปยัง account เดียว หรือหลาย account
- **Sequential account pattern**: Administrator, admin, Guest, user, user1, backup (common RDP target)
- **Event ID 4624 Type 10 จาก new IP**: login สำเร็จจาก IP ที่ไม่เคย login มาก่อน
- **Non-business hour RDP**: successful RDP login ช่วงกลางคืนหรือวันหยุดจาก IP ต่างประเทศ
- **Event ID 4740**: account lockout หลายครั้งในช่วงเวลาสั้น
- **Event 1149 failure burst**: authentication failure burst ใน TerminalServices log
- **Source IP**: Tor exit node, known scanning IP (Shodan-indexed scanner), commercial VPN, ต่างประเทศที่ไม่มี business

## Phase: containment
### Sub: short_term
1. **Block source IP** ที่ Firewall ทันที: `netsh advfirewall firewall add rule name="Block RDP Attacker" dir=in action=block remoteip=<attacker_ip> protocol=TCP localport=3389`
2. **ปิด RDP จาก internet** โดย restrict inbound 3389 เฉพาะ VPN IP range หรือ jump host IP
3. **Lock account** ที่ถูก brute force: `Disable-ADAccount -Identity <username>`
4. **Reset password** ของ account ที่ประสบ successful login ทันที
5. **Terminate RDP session** ที่สงสัย: `logoff <session_id> /server:<hostname>`
6. **เปิด Account Lockout Policy** ถ้ายังไม่มี: lockout หลัง 5 failures, duration 30 นาที
7. **บังคับ NLA** ที่ RDP host ถ้ายังไม่ได้เปิด: Computer Config → Administrative Templates → RDP Host → Require NLA

### Sub: long_term
- **ย้าย RDP ไปยัง VPN**: ไม่ควร expose RDP โดยตรงบน internet อย่างเด็ดขาด
- Deploy **RDP Gateway (Remote Desktop Gateway)** สำหรับ centralized RDP access control
- บังคับ **MFA สำหรับ RDP**: ใช้ Duo Security, Azure MFA, หรือ NPS Extension
- เปลี่ยน **RDP port** จาก default 3389 เป็น port อื่น (security through obscurity — ลด noise ไม่ใช่ security)
- ทำ **Just-in-Time (JIT) RDP access**: เปิด port 3389 เฉพาะเมื่อต้องการ ผ่าน Azure Security Center/AWS SSM

### Sub: evidence_preservation
- Export **Windows Security Event Log**: `wevtutil epl Security C:\evidence\security_rdp.evtx`
- Export **TerminalServices log**: `wevtutil epl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" C:\evidence\rdp_session.evtx`
- บันทึก **RDP session activity** หลัง successful login: Sysmon log, prefetch files ใน `%WINDIR%\Prefetch`
- เก็บ **Firewall log** ที่แสดง source IP และ connection pattern
- หากมี RDP session recording solution บันทึก **session replay** ของ attacker session

## Phase: eradication
### Sub: process_removal
- ตรวจสอบ **process ที่ถูก launch ใน RDP session** ของ attacker:
  ```powershell
  Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
    Where-Object {$_.Message -match "LogonId"} | Select-Object TimeCreated, Message | Format-List
  ```
- Kill **backdoor process** ที่อาจถูก install ผ่าน RDP session
- ลบ **tool ที่ถูก upload** ผ่าน RDP clipboard/file transfer: ตรวจสอบ `%TEMP%` และ Desktop

### Sub: persistence_removal
- ลบ **local user** ที่ attacker สร้างผ่าน RDP session: `Get-LocalUser | Where-Object {$_.Enabled -eq $true}`
- ลบ **scheduled task** ที่สร้างผ่าน RDP session
- ตรวจสอบ **registry Run key** ที่อาจถูก set สำหรับ persistence
- ตรวจสอบ **Remote Desktop Users group**: `Get-LocalGroupMember -Group "Remote Desktop Users"`

### Sub: patching
- อัปเดต **Windows** โดยเฉพาะ patch สำหรับ RDP vulnerability (BlueKeep CVE-2019-0708, DejaBlue)
- ตรวจสอบและ apply **RDP-related KB** ทั้งหมดที่ยังไม่ได้ install
- บังคับ **NLA** บน RDP host ทุกเครื่อง: `Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1`
- ทบทวน **Firewall rule** ให้ RDP เข้าถึงได้เฉพาะ authorized IP range เท่านั้น

## Phase: post_incident
### Sub: lessons_learned
- ตรวจสอบว่า **RDP exposed โดยตรงจาก internet** เพราะอะไร และ approved โดยใคร
- ประเมินว่า **Account Lockout Policy** ทำงานหรือไม่ และ threshold เหมาะสมหรือไม่
- วิเคราะห์ว่า **MFA** มีการใช้งานสำหรับ RDP access หรือไม่
- ตรวจสอบว่า **SIEM alert** trigger ทันที event 4625 burst หรือล่าช้า
- ประเมินว่า successful login มีผลกระทบ downstream อะไรบ้าง

### Sub: improvements
- **ปิด RDP จาก internet** ทันที และบังคับใช้ VPN + MFA สำหรับ remote access ทุก case
- Deploy **RDP Gateway** พร้อม MFA integration
- เพิ่ม **SIEM alert** สำหรับ RDP brute force (Event 4625 Type 10 > threshold) และ RDP login จาก new country
- ทำ **regular external port scan** เพื่อ identify exposed RDP port ก่อนที่ attacker จะพบ
- จัด **security awareness training** เรื่อง remote access security policy
