---
threat_name: Credential Dumping
technique_ids: ["T1003.001", "T1078", "T1550.002"]
severity: Critical
source_doc: Credential_Dumping_IR_Playbook_v1
---

## เอกสารอ้างอิง — Preparation, Detection & Post-Incident Review (ไม่ถูก ingest เป็น RAG chunk)

> ขอบเขต proposal §3.3 กำหนดให้ playbook เชิงรับมีแค่ 3 phase: Containment / Eradication / Recovery
> เนื้อหาด้านล่างเก็บไว้เป็นข้อมูลอ้างอิง ไม่ได้อยู่ใต้ `## Phase:` จึงไม่ถูก `01_ingest.py` ดึงเข้า ChromaDB

**Tool readiness:** Mimikatz บน sandbox สำหรับศึกษา, Sysmon (enable Event ID 10 ProcessAccess เล็ง `lsass.exe`), Windows Credential Guard (Win10/Server2016+), Defender for Identity/Microsoft Sentinel พร้อม alert rule LSASS access, procdump.exe (Sysinternals) สำหรับ forensic ที่ถูกต้อง, script ตรวจ Protected Users Security Group, hashcat บน air-gapped machine

**Team roles:** Incident Commander (ประเมินขอบเขต credential ที่ถูก dump), Windows/AD Specialist (reset password/disable account/ตรวจ Kerberos ticket), SOC Analyst L2/L3 (hunt ด้วย Sysmon Event ID 10), Threat Intelligence Analyst (ระบุ malware family เช่น Mimikatz/SharpKatz/SafetyKatz), Forensic Analyst (collect memory dump ตาม chain of custody), CISO (ประเมิน business risk)

**Comm plan:** แจ้ง AD Admin reset krbtgt ทันที (สำคัญมากสำหรับ Pass-the-Hash/Golden Ticket), แจ้ง executive team ถ้า credential ผู้บริหารถูก compromise, ใช้ out-of-band communication เพราะ attacker อาจ intercept email, ประสาน legal team เรื่อง data breach notification obligation

**Log sources:** Sysmon Event ID 10 (ProcessAccess ไปยัง lsass.exe ด้วย PROCESS_VM_READ), Windows Security Event 4656 (request handle to LSASS), Event 4624 Logon Type 9 (NewCredentials = Pass-the-Hash), Event 4672 (SeDebugPrivilege), Windows Defender alert (Mimikatz/WCE/PWDumpX signature), Sysmon Event ID 7 (comsvcs.dll โหลดผิดที่), EDR alert สำหรับ LSASS memory access

**IoC list:** Sysmon Event 10 GrantedAccess=0x1010/0x1410 ไปยัง lsass.exe จาก process แปลกปลอม, process name mimikatz.exe/wce.exe/pwdump.exe/procdump.exe ในบริบทผิดปกติ, command line `procdump -ma lsass.exe` หรือ `rundll32 comsvcs.dll MiniDump`, ไฟล์ .dmp ใน temp/staging directory, registry WDigest UseLogonCredential=1, Event 4673 ใช้ SeDebugPrivilege ผิดปกติ, dump file ถูก transfer ออกไปยัง C2

**Lessons learned:** Credential Guard เปิดอยู่หรือไม่และทำไมไม่เปิด, SIEM alert สำหรับ LSASS process access ทำงานก่อนเหตุการณ์หรือไม่, attacker ได้ privilege escalation มาได้อย่างไรก่อนถึงขั้น dump, dwell time นานแค่ไหนก่อนตรวจพบ, ผลกระทบต่อระบบอื่น (lateral movement scope)

**Improvements ที่ควรผลักดันต่อ:** บังคับ Credential Guard ผ่าน Group Policy ทุกเครื่อง, deploy Microsoft Defender for Identity, เพิ่ม SIEM rule สำหรับ Sysmon Event 10 GrantedAccess=0x1010, implement LAPS, ทบทวน Tier model ของ AD administration

## Phase: containment
### Sub: short_term
1. **Isolate เครื่องที่ถูก compromise** จาก network ทันที: ปิด network adapter หรือ ย้ายเข้า VLAN กักกัน
2. **Reset password** ของ account ที่ถูก dump ทุก account โดยเฉพาะ privileged account
3. **Reset krbtgt account password 2 ครั้ง** (ต้องทำ 2 รอบเพื่อ invalidate Kerberos ticket ทั้งหมด):
   ```powershell
   Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (Read-Host -AsSecureString)
   ```
4. **Revoke Kerberos TGT** ทั้งหมดสำหรับ compromised account: `klist purge` บนทุกเครื่อง
5. **เปิด Protected Users Security Group** สำหรับ privileged account เพื่อบังคับ Kerberos และ block NTLM
6. **Block SMB outbound** จากเครื่องที่ถูก compromise เพื่อหยุด hash relay: `netsh advfirewall firewall add rule name="Block SMB Out" dir=out action=block protocol=TCP remoteport=445`
7. **Force logoff** session ของ compromised account ทุก session

### Sub: long_term
- เปิดใช้ **Windows Credential Guard** บน Windows 10/Server 2016+ เพื่อ protect LSASS ด้วย virtualization
- ปิด **WDigest** ใน registry: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` → `UseLogonCredential = 0`
- ใช้ **LAPS (Local Administrator Password Solution)** เพื่อ randomize local admin password ทุกเครื่อง
- Implement **Privileged Access Workstation (PAW)** สำหรับ admin account
- ตรวจสอบและจำกัด **SeDebugPrivilege** ในทุก machine

### Sub: evidence_preservation
- ทำ **memory dump** ของ compromised machine: `winpmem_mini.exe -o C:\evidence\memory.dmp`
- Export **Sysmon Event ID 10 logs** ช่วง incident: `wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\evidence\sysmon.evtx`
- เก็บ **Security Event Log** (Event 4624, 4625, 4648, 4672): `wevtutil epl Security C:\evidence\security.evtx`
- Hash ทุก evidence file และบันทึกใน chain of custody document
- เก็บ **dump file** (ถ้าพบ) พร้อม hash เพื่อ analyze offline

## Phase: eradication
### Sub: process_removal
- Kill **malware process** ที่ใช้ dump credential:
  ```powershell
  Get-Process | Where-Object {$_.Name -match "mimikatz|wce|pwdump"} | Stop-Process -Force
  ```
- ตรวจสอบ **injected process**: `Get-Process | Where-Object {$_.Modules.FileName -match "\.tmp|AppData"}`
- Scan ด้วย **Windows Defender / EDR** offline scan หาก malware ซ่อนตัวใน rootkit

### Sub: persistence_removal
- ลบ **scheduled task** ที่ถูกสร้างสำหรับ re-dump credential:
  ```powershell
  Get-ScheduledTask | Where-Object {$_.Actions.Execute -match "mimikatz|procdump|rundll32"} | Unregister-ScheduledTask
  ```
- ตรวจสอบ **registry Run keys** และ **startup folder**: `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- ลบ **malware payload** จาก disk รวมถึง dump files ที่ยังหลงเหลือ
- Reset **service account password** ทุกตัวที่อาจถูก dump

### Sub: patching
- อัปเดต **Windows** เพื่อ patch vulnerabilities ที่ Mimikatz exploit (KB ที่เกี่ยวข้อง)
- เปิด **Windows Defender Credential Guard** via Group Policy
- ติดตั้ง **Microsoft Defender for Identity** สำหรับ detect Mimikatz-like behavior บน domain level
- ทบทวน **local admin rights**: ลด จำนวน user ที่มี local admin บนเครื่อง

## Phase: recovery
### Sub: service_restoration
- **คืนสิทธิ์บัญชีทีละขั้น** หลังยืนยัน Credential Guard/WDigest ถูกปิดใช้ (`UseLogonCredential=0`) บนเครื่องที่เกี่ยวข้องแล้วเท่านั้น — ไม่คืนสิทธิ์ก่อนปิดช่องโหว่นี้
- **ยืนยันการ reset krbtgt สำเร็จ 2 ครั้ง** และ replicate ไปทุก Domain Controller ก่อนประกาศว่าปิดเคส (`repadmin /replsummary`)
- **คืนเครื่องเข้าเครือข่าย** หลังผ่าน offline scan (EDR/AV) ยืนยันสะอาด ไม่ใช่แค่ isolate แล้วรีบคืนกลับ
- แจ้ง **Application Owner / CISO** ว่าระบบกลับมาปกติ พร้อมระบุ credential ชุดใดถูก rotate ไปแล้วบ้าง

### Sub: validation_monitoring
- เฝ้าระวัง **Sysmon Event ID 10** (LSASS access) และ **Event 4672** ต่ออีกอย่างน้อย 14 วันหลังปิดเคส (มัลแวร์ตระกูลนี้มักกลับมาลองซ้ำ)
- ยืนยันว่า **Kerberos ticket เก่าทั้งหมดถูก invalidate จริง**: ทดสอบว่า golden ticket เดิม (ถ้ามี) ใช้ไม่ได้แล้ว
- ตรวจสอบ **lateral movement scope** ว่าไม่มี credential ที่ dump ไปแล้วถูกใช้งานที่เครื่องอื่นหลงเหลือ
- ทดสอบ login จริงของบัญชีที่ reset password เพื่อยืนยันว่าใช้งานได้ปกติ

### Sub: closure
- บันทึก **credential ทั้งหมดที่ถูก rotate** (user, service account, krbtgt) ลง incident ticket พร้อมเวลา
- ยืนยันกับ **Forensic Analyst** ว่าหลักฐาน (memory dump, log) ถูกเก็บและ hash ครบตาม chain of custody ก่อนปิดเคส
- ส่งต่อ **Credential Guard / LAPS rollout ที่ยังไม่ครบทุกเครื่อง** เป็น follow-up item พร้อมกำหนดเวลา
