---
threat_name: "OS Credential Dumping (Technique Defense Guide)"
technique_ids: ["T1003", "T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006"]
severity: High
source_doc: "T1003_Technique_Defense_Guide_v1"
doc_type: defense
---

> เอกสารนี้คือ KB ส่วนที่ 2 ตามขอบเขต proposal §3.2 — "เอกสารแนวทางป้องกันรายเทคนิค"
> ต่างจาก threat playbook (`playbooks/*.md`) ตรงที่ไม่ผูกกับ threat scenario ใดโดยเฉพาะ
> เป็นแนวทางระดับ technique ล้วนๆ ใช้ประกอบกับ threat playbook เมื่อ alert ไม่ตรง threat
> เล่มไหนเป๊ะ แต่ technique ตรง (grounding tier "technique_composed" ตาม ARCHITECTURE.md §4)

> **หลักคิดหลักของเทคนิคนี้:** การ dump credential ทุก variant ต้องการ **สิทธิ์ระดับ SYSTEM/
> local admin บน host** หรือ **สิทธิ์ที่ DC/replication** เป็นเงื่อนไขก่อนเสมอ — จุดตัดที่คุ้มสุดจึงเป็น
> การ**จำกัดสิทธิ์สูงและปกป้องที่เก็บ credential** ไม่ใช่ไล่ตามเครื่องมือ dump ทีละตัว สิ่งที่ต้อง
> แยกให้ออกคือ **ขอบเขตของ credential ที่หลุด**: dump บน host เดียว (LSASS/SAM/LSA/cached)
> = เฉพาะบัญชีที่เคยล็อกอินเครื่องนั้น แต่ **NTDS/DCSync = ทั้งโดเมน** (รวม krbtgt) ต้องยกระดับเป็น
> domain compromise — และ follow-on จริงคือ Use Alternate Authentication Material (T1550) ที่
> เอา hash/ticket ที่ได้ไปใช้ต่อ ต้องกันที่ payoff นั้นด้วย

> **หมายเหตุการจัดหัวข้อ:** section ที่ tag `[T1003]` คือ control ระดับครอบทั้งเทคนิค (ใช้ได้ทุก
> variant) ส่วน `[T1003.00x]` คือ control เจาะจงตามแหล่งที่ดึง credential เพราะที่เก็บและวิธีปกป้อง
> ต่างกัน (LSASS memory / registry hive / NTDS database / replication) — โครงนี้ช่วยให้ retrieval
> ดึงได้ถูกชั้น ไม่ว่า alert จะ map มาที่ base technique หรือลงลึกถึง sub (ARCHITECTURE.md §4.3–4.4)

## Phase: containment
### Sub: scope_and_isolate [T1003]
- **ตัดสินขอบเขตก่อนเลือกมาตรการ**: ถ้าเป็น NTDS/DCSync ให้ถือว่า **ทุก credential ในโดเมนหลุด** (รวม krbtgt) → ยกระดับเป็น domain compromise ทันที; ถ้าเป็น dump บน host เดียว blast radius = เฉพาะบัญชีที่เคยล็อกอินเครื่องนั้น — contain ตามระดับที่ scope ได้
- **ตัด follow-on ที่เป็นเป้าหมายจริง**: hash/secret ที่ dump ได้จะถูกเอาไปใช้เป็น Use Alternate Authentication Material (T1550 — Pass-the-Hash/Ticket) — ระงับ/ลดสิทธิ์บัญชีที่หลุด และ revoke session/ticket ที่ปลายทาง ไม่ใช่แค่ล้างเครื่องมือ dump
- เก็บ **หลักฐานทันที** (Sysmon EID 10 การเข้าถึง LSASS, Event 4662 replication, memory image, registry hive ที่ถูกแตะ) ก่อน remediate — สถานะบางส่วนอยู่ในหน่วยความจำ หายหลัง reboot

### Sub: host_memory_and_secret_containment [T1003.001, T1003.004, T1003.005]
- **Isolate host และบังคับ reset credential ที่ resident บนเครื่องนั้น**: LSASS memory (.001), LSA Secrets (.004), และ cached domain credentials (.005) เปิดเผยบัญชีที่เคยล็อกอิน/service ที่รันบน host — ถือว่าบัญชีเหล่านั้นหลุดทั้งหมด บังคับ reset + revoke session
- ให้ความสำคัญกับ **บัญชี privileged ที่เคยล็อกอินเครื่องที่โดน** ก่อน (domain admin, service account สิทธิ์สูง) เพราะ hash ของมันมีมูลค่าต่อการขยายผลสูงสุด

### Sub: local_hive_containment [T1003.002]
- **รีเซ็ตรหัส local account ทั้งหมดบน host ที่โดน** (โดยเฉพาะ local administrator): SAM hive เก็บ hash ของบัญชี local — ถ้าใช้รหัส local admin ร่วมกันหลายเครื่อง ให้ถือว่าทุกเครื่องที่ใช้รหัสเดียวกันหลุดด้วย และเร่ง rollout LAPS

### Sub: domain_db_containment [T1003.003, T1003.006]
- **ถือเป็น domain compromise เต็มรูปแบบ**: NTDS.dit (.003) และ DCSync (.006) ดึง hash ได้ทั้งโดเมน — เริ่ม **reset krbtgt สองรอบ** (ดู T1558.001), reset บัญชี privileged และวางแผน mass password reset
- **ตัดสิทธิ์ replication ที่ผิดปกติทันที**: เพิกถอนสิทธิ์ "Replicating Directory Changes / All" ออกจาก principal ที่ไม่ใช่ DC (DCSync อาศัยสิทธิ์นี้) และ isolate DC/host ที่เป็นต้นทางการ replicate ผิดปกติ

## Phase: eradication
### Sub: privileged_access_hardening [T1003]
- **จำกัด local admin และทำ tiered admin model** (M1026): การ dump ทุก variant ต้องมีสิทธิ์สูงก่อน — บังคับ LAPS ให้รหัส local admin ต่างกันทุกเครื่อง, ห้าม domain admin ล็อกอิน workstation ทั่วไป (กันไม่ให้ hash สิทธิ์สูงไปนอนบนเครื่องเสี่ยง)
- ย้ายบัญชี privileged เข้า **Protected Users group** และปิด delegation ที่ไม่จำเป็น — ลดทั้ง credential ที่ถูก cache และมูลค่าของสิ่งที่ dump ได้

### Sub: lsass_protection [T1003.001]
- เปิด **Credential Guard** และ **LSASS เป็น Protected Process Light (RunAsPPL)** (M1043): กันการอ่าน LSASS memory ตรงๆ ซึ่งเป็นวิธี dump logon credential ที่พบบ่อยสุด
- เปิด **Attack Surface Reduction rule "Block credential stealing from lsass.exe"** และ application control กันเครื่องมือ dump (Mimikatz/comsvcs.dll) ที่ระดับ execution

### Sub: registry_and_cached_hardening [T1003.002, T1003.004, T1003.005]
- **ปกป้อง registry hive ที่เก็บ secret** (SAM/SECURITY): จำกัดสิทธิ์ให้เฉพาะ SYSTEM/admin และเฝ้าการเข้าถึง/สำเนา hive — ตัดทั้ง SAM dump (.002) และ LSA Secrets (.004)
- **ลดจำนวน cached logon** บนเครื่องสำคัญ/เสี่ยง (.005) และใช้ Protected Users (ไม่ cache) สำหรับบัญชี privileged — ลดของที่ดึงไปแครกแบบ offline (DCC2 แครกช้าแต่ได้ถ้ารหัสอ่อน)

### Sub: ntds_protection [T1003.003]
- **ปกป้อง NTDS.dit และสำเนาทั้งหมด** (M1041): เข้ารหัส/จำกัดสิทธิ์ backup, VSS snapshot, และ IFM media ของ DC — บ่อยครั้งผู้โจมตีดึงจาก backup ที่ป้องกันหลวม ไม่ใช่จาก DC สด
- **จำกัดผู้ที่ล็อกอิน/รัน code บน DC ได้** ให้เหลือเฉพาะ Domain/Enterprise Admin ที่จำเป็น และแยก DC ออกจากการใช้งานทั่วไป — DC คือจุดเดียวที่ NTDS.dit อยู่

### Sub: dcsync_lockdown [T1003.006]
- **Audit และเพิกถอนสิทธิ์ replication** ("Replicating Directory Changes" + "…All" + "…In Filtered Set") ให้เหลือเฉพาะ **บัญชี DC เท่านั้น** (M1015) — บัญชี user/service ที่มีสิทธิ์นี้คือช่องทาง DCSync โดยตรง
- ตรวจ **ACL ของ domain object** หา principal ที่ถูกเพิ่มสิทธิ์ replication อย่างผิดปกติ (มักเป็น backdoor ที่ผู้โจมตีวางไว้) แล้วลบทิ้ง

## Phase: recovery
### Sub: credential_reset_baseline [T1003]
- **รีเซ็ต credential ตามขอบเขตที่ scope ได้**: host เดียว → บัญชีที่เคยล็อกอินเครื่องนั้น; domain-wide (NTDS/DCSync) → mass reset รวม krbtgt สองรอบ + service account ทั้งชุด — ไม่รีเซ็ตครึ่งๆ กลางๆ เพราะ hash ที่เหลือยังใช้ Pass-the-Hash ได้
- ตั้ง **least-privilege + tiered admin เป็น baseline ใหม่** และทบทวนสิทธิ์สูงเป็นรอบ เพื่อลด credential ที่จะ dump ได้ในอนาคต

### Sub: endpoint_dumping_detection [T1003.001, T1003.002, T1003.004, T1003.005]
- ตั้ง detection บน **การเข้าถึง LSASS ที่น่าสงสัย** (Sysmon EID 10 handle ไป lsass.exe จาก process แปลก), การสำเนา SAM/SECURITY hive, และการรันเครื่องมือ dump — ส่งเข้า SIEM เป็น baseline
- เฝ้า **การอ่าน registry secret และ shadow copy** ที่ผิดรูป (เช่น `reg save hklm\sam`, การเรียก VSS นอกตารางเวลา backup)

### Sub: domain_db_detection [T1003.003, T1003.006]
- ตั้ง alert บน **Event 4662 ที่มี replication GUID (DsGetNCChanges)** จาก **source ที่ไม่ใช่ DC** — เป็นลายเซ็นตรงของ DCSync (.006)
- เฝ้า **การเข้าถึง/สำเนา NTDS.dit และ VSS บน DC** และการสร้าง IFM/`ntdsutil` ที่ไม่ได้อยู่ในแผน — baseline สำหรับ incident ครั้งถัดไป
