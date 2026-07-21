---
threat_name: RDP Brute Force
technique_ids: ["T1110.001", "T1021.001", "T1078"]
severity: High
source_doc: RDP_Brute_Force_IR_Playbook_v1
---

## เอกสารอ้างอิง — Preparation, Detection & Post-Incident Review (ไม่ถูก ingest เป็น RAG chunk)

> ขอบเขต proposal §3.3 กำหนดให้ playbook เชิงรับมีแค่ 3 phase: Containment / Eradication / Recovery
> เนื้อหาด้านล่างเก็บไว้เป็นข้อมูลอ้างอิง ไม่ได้อยู่ใต้ `## Phase:` จึงไม่ถูก `01_ingest.py` ดึงเข้า ChromaDB

**Tool readiness:** Windows Security Audit Policy สำหรับ Event 4625/4624/4778, RDPGuard หรือ fail2ban สำหรับ Windows, NLA (Network Level Authentication), GeoIP database, Shodan/Censys lookup ตรวจว่า RDP port expose บน internet ไหม, Sysmon สำหรับ process หลัง RDP login, list ของ Tor exit node/commercial VPN range

**Team roles:** Incident Commander (ตัดสินใจ block RDP จาก internet ทันทีหรือ monitor ต่อ), Windows/AD Admin (lockout/reset/ตรวจ active session), Network Engineer (block source IP, ตรวจว่า RDP expose ตรง), SOC Analyst L2/L3 (monitor 4625/4624 real-time), Forensic Analyst (เก็บ evidence จาก session ที่สำเร็จ), Help Desk (verify identity ก่อน unlock)

**Comm plan:** แจ้ง Windows Admin ทันทีเมื่อ Event 4625 > 50 ครั้ง/5 นาทีจาก IP เดียว, ส่ง P1 Alert ทันทีถ้าพบ Event 4624 Type 10 จาก IP ต่างประเทศ, แจ้ง Network team ประเมินว่า RDP ควร expose ตรงหรือไม่, ประสาน application owner assess business impact

**Log sources:** Windows Security Event 4625 (failed logon), 4624 Type 10 (successful RemoteInteractive), 4778 (session reconnect), 4740 (account lockout), TerminalServices-RemoteConnectionManager Event 1149, TerminalServices-LocalSessionManager Event 21/23/24, Sysmon Event ID 1 (process หลัง RDP login), Firewall log (inbound port 3389)

**IoC list:** Event 4625 Type 10 > 20 ครั้ง/5 นาทีต่อ IP, sequential account pattern (Administrator, admin, Guest, user1, backup), Event 4624 Type 10 จาก IP ใหม่ที่ไม่เคย login, non-business hour RDP จากต่างประเทศ, Event 4740 ซ้ำในเวลาสั้น, Event 1149 failure burst, source IP เป็น Tor/scanner/VPN/ต่างประเทศไม่มี business

**Lessons learned:** RDP expose ตรงจาก internet เพราะอะไรและใครอนุมัติ, Account Lockout Policy ทำงานและ threshold เหมาะสมหรือไม่, มีการใช้ MFA สำหรับ RDP หรือไม่, SIEM alert trigger ทันทีหรือล่าช้า, ผลกระทบ downstream ของ successful login

**Improvements ที่ควรผลักดันต่อ:** ปิด RDP จาก internet ทันทีบังคับ VPN+MFA ทุกกรณี, deploy RDP Gateway พร้อม MFA, เพิ่ม SIEM alert สำหรับ RDP brute force + login จากประเทศใหม่, ทำ external port scan สม่ำเสมอ, จัด security awareness training

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

## Phase: recovery
### Sub: service_restoration
- **เปิด RDP กลับมาผ่าน RDP Gateway/VPN เท่านั้น** ห้าม expose port 3389 ตรงสู่ internet เหมือนก่อนเกิดเหตุ
- **Unlock/reset account** เฉพาะหลัง verify identity ผ่านช่องทาง out-of-band และยืนยันว่าเปิด NLA + MFA แล้ว
- แจ้ง **Application Owner** ว่า server กลับมาใช้งานได้ พร้อมเงื่อนไขใหม่ (ต้องผ่าน gateway, ต้องมี MFA)
- ทยอย **คืน Firewall rule** ให้ RDP เข้าถึงได้เฉพาะ IP range ที่ได้รับอนุญาต ไม่เปิดกว้างเหมือนเดิม

### Sub: validation_monitoring
- เฝ้าระวัง **Event 4625/4624 Type 10 ซ้ำ** จาก IP หรือ account เดิมอีกอย่างน้อย 7 วัน
- ยืนยันว่า **NLA + MFA บังคับใช้จริง** ด้วยการทดสอบ login จริงหนึ่งรอบผ่าน gateway ใหม่
- ตรวจสอบว่าไม่มี **RDP session ค้าง** หรือ scheduled task ที่ attacker สร้างไว้หลงเหลือ
- ทำ **external port scan ซ้ำ** ยืนยันว่า 3389 ไม่ expose ตรงสู่ internet อีกแล้ว

### Sub: closure
- บันทึก **สรุปเหตุการณ์และมาตรการที่คงไว้ถาวร** (RDP Gateway, MFA, Firewall rule ใหม่) ลง incident ticket
- ยืนยันกับ **Network Engineer** ว่า config การ block/gateway ผ่านการตรวจทานแล้วไม่ใช่แค่ตั้งชั่วคราว
- ส่งต่อ **RDP Gateway/MFA rollout ที่ยังไม่ครบทุกเครื่อง** เป็น follow-up item พร้อมกำหนดเวลา
