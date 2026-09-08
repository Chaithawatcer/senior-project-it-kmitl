---
threat_name: "Modify Authentication Process (Technique Defense Guide)"
technique_ids: ["T1556", "T1556.001", "T1556.002"]
severity: High
source_doc: "T1556_Technique_Defense_Guide_v1"
doc_type: defense
---

> เอกสารนี้คือ KB ส่วนที่ 2 ตามขอบเขต proposal §3.2 — "เอกสารแนวทางป้องกันรายเทคนิค"
> ต่างจาก threat playbook (`playbooks/*.md`) ตรงที่ไม่ผูกกับ threat scenario ใดโดยเฉพาะ
> เป็นแนวทางระดับ technique ล้วนๆ ใช้ประกอบกับ threat playbook เมื่อ alert ไม่ตรง threat
> เล่มไหนเป๊ะ แต่ technique ตรง (grounding tier "technique_composed" ตาม ARCHITECTURE.md §4)

> **หลักคิดหลักของเทคนิคนี้:** ผู้โจมตีไม่ขโมย credential แต่ **แก้กระบวนการ authenticate ที่ DC/
> LSA เอง** เพื่อให้ตัวเองผ่านหรือดัก credential ของคนอื่น — Skeleton Key (.001) ฝัง master
> password ใน LSASS ของ DC ให้ล็อกอินเป็นใครก็ได้, Password Filter DLL (.002) ลงทะเบียน DLL
> ใน LSA เพื่อดัก **รหัสผ่าน plaintext ตอนเปลี่ยนรหัส** ทั้งคู่ต้องมี **สิทธิ์ระดับ admin/SYSTEM บน DC**
> เป็นเงื่อนไขก่อน จึงมักเป็นขั้น persistence หลังยึด DC ได้แล้ว — การป้องกันตัดที่ **ความสมบูรณ์ของ
> DC/LSA** และ **การเฝ้า config การ auth** ไม่ใช่ที่ชั้น login ของผู้ใช้

> **หมายเหตุการจัดหัวข้อ:** section ที่ tag `[T1556]` คือ control ระดับครอบทั้งเทคนิค ส่วน
> `[T1556.001]`/`[T1556.002]` คือ control เจาะจงตามวิธีแก้ auth (in-memory LSASS patch vs LSA
> notification package) — โครงนี้ช่วยให้ retrieval ดึงได้ถูกชั้น ไม่ว่า alert จะ map มาที่ base
> technique หรือลงลึกถึง sub (ARCHITECTURE.md §4.3–4.4)

## Phase: preparation
### Sub: dc_auth_baseline [T1556]
- ตั้ง **baseline authentication package/module ที่ LSASS บน DC โหลดตามปกติ** และจำกัดสิทธิ์ที่แก้ authentication process ได้ (Domain Admin/DC access เท่านั้น) — รู้ล่วงหน้าว่าอะไรคือของแท้
- เปิด **LSA Protection (RunAsPPL)** บน DC เชิงป้องกัน เพื่อกันการ patch/inject authentication logic

### Sub: skeleton_key_readiness [T1556.001]
- จำกัด **debug privilege บน DC** และเตรียม monitor การ patch memory ของ LSASS — skeleton key ต้องเขียนหน่วยความจำ LSASS บน DC

### Sub: password_filter_readiness [T1556.002]
- ทำ **inventory Notification Packages** ใน `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` ที่โหลดตอน boot และตั้ง baseline ว่ามี password filter DLL ใดที่ถูกต้อง เพื่อจับ DLL แปลกปลอมภายหลัง

## Phase: detection_analysis
### Sub: dc_auth_anomaly_detection [T1556]
- เฝ้า **LSASS บน DC โหลด module/DLL ผิดปกติ**, การ restart LSASS โดยไม่คาดหมาย, และ logon สำเร็จด้วยบัญชี/รหัสที่ไม่ควรใช้ได้ (บ่งชี้ backdoor authentication)
- ยืนยันขอบเขต: DC ที่กระทบ, บัญชีที่ถูกใช้ และช่วงเวลา

### Sub: skeleton_key_detection [T1556.001]
- เฝ้า **process access `lsass.exe` บน DC (Sysmon EID 10)** และ pattern แบบ `mimikatz misc::skeleton`, การเปิด debug บน DC

### Sub: password_filter_detection [T1556.002]
- เฝ้า **registry write ที่ `...\Lsa\Notification Packages`** และการที่ `lsass` โหลด DLL ใหม่ที่ไม่อยู่ใน baseline

## Phase: containment
### Sub: scope_and_isolate [T1556]
- **ถือเป็น DC compromise**: ทั้งสอง variant ต้องมีสิทธิ์สูงบน DC อยู่ก่อน — ถ้าพบ ให้สันนิษฐานว่าผู้โจมตีมี domain admin แล้ว isolate DC ที่กระทบและเริ่ม scope ว่าถูกยึดตั้งแต่เมื่อไหร่
- **ตัด follow-on**: การแก้ auth เปิดทางให้ล็อกอินเป็นใครก็ได้ (Skeleton Key) หรือได้รหัส plaintext (Password Filter) → เร่ง reset credential ที่กระทบและ revoke session privileged
- เก็บหลักฐาน **memory ของ DC (lsass), registry LSA (Notification/Authentication Packages), Event การล็อกอินที่ผิดปกติ** ก่อน remediate

### Sub: skeleton_key_containment [T1556.001]
- **Reboot DC ที่ติด Skeleton Key**: มันเป็น in-memory patch ของ LSASS ไม่ persistent ข้าม reboot — reboot ล้างตัว key ออกได้ทันที แต่ต้องตัดทางที่ผู้โจมตี re-inject ควบคู่ (ไม่งั้นกลับมาใหม่)
- บังคับ **reset บัญชี privileged** เพราะช่วงที่ Skeleton Key ทำงาน ผู้โจมตีล็อกอินเป็น domain admin ด้วย master password ได้โดยไม่ต้องรู้รหัสจริง

### Sub: password_filter_containment [T1556.002]
- **ถอดทะเบียน Password Filter DLL ที่ไม่ได้รับอนุญาต** ออกจาก registry (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa` → `Notification Packages`) และลบไฟล์ DLL — แล้ว restart ตามที่จำเป็น
- **สันนิษฐานว่ารหัสผ่านที่ถูกเปลี่ยนช่วง DLL ทำงานถูกดักเป็น plaintext ทั้งหมด** → บังคับ reset รอบใหม่ให้บัญชีเหล่านั้น (การ reset ครั้งแรกที่ผ่าน filter ก็ถูกดักไปแล้ว)

## Phase: eradication
### Sub: dc_integrity_hardening [T1556]
- **ปิดต้นตอสิทธิ์ที่ DC**: หาช่องที่ผู้โจมตีได้ admin/SYSTEM บน DC (credential dumping, delegation, ACL) แล้วปิด — ถ้าไม่ปิด จะกลับมาแก้ auth ซ้ำได้เสมอ
- ทำ **tiered admin + Protected Users** และจำกัดผู้ที่ล็อกอิน/รัน code บน DC ให้เหลือเท่าที่จำเป็น (M1026) — ลดโอกาสเข้าถึง LSA ตั้งแต่ต้น

### Sub: lsass_protection [T1556.001]
- เปิด **Credential Guard + LSASS Protected Process Light (RunAsPPL)** (M1043): กันการ inject/patch LSASS ซึ่งเป็นวิธีฝัง Skeleton Key
- ใช้ **application control (WDAC/AppLocker)** บน DC กันการรัน binary/driver ที่ไม่ได้เซ็นเชื่อถือ — ปิดเครื่องมือที่ใช้ inject

### Sub: lsa_config_hardening [T1556.002]
- **Audit และ lock ค่า LSA "Notification Packages"/"Authentication Packages"** ให้เหลือเฉพาะ DLL ที่รับรอง และตั้ง alert เมื่อมีการเปลี่ยน (M1047)
- เปิด **LSASS PPL + WDAC** เพื่อบล็อกการโหลด Password Filter DLL ที่ไม่ได้เซ็น — LSA จะไม่โหลด DLL นอกรายการที่เชื่อถือ

## Phase: recovery
### Sub: auth_config_monitoring_baseline [T1556]
- ตั้ง **monitoring การเปลี่ยน registry LSA** (Notification/Authentication Packages, Security Packages) และ **การโหลด DLL ที่ไม่ได้เซ็นใน lsass** เป็น baseline ส่งเข้า SIEM
- เฝ้า **สัญญาณ Skeleton Key**: การล็อกอินสำเร็จที่ downgrade เป็น RC4 ผิดปกติ หรือ pattern การ auth ที่ succeed ทั้งที่ควร fail

### Sub: dc_auth_audit [T1556]
- ทำ **audit config การ auth ของ DC เป็นรอบ** (LSA packages, password filter, สิทธิ์ที่ล็อกอิน DC ได้) เทียบ baseline ที่ยืนยันแล้ว — ตัดสิ่งที่โผล่มาผิดปกติ
- ทบทวน **สิทธิ์ privileged ที่แตะ DC ได้** เป็นรอบ เพื่อกันไม่ให้ผู้โจมตีกลับเข้าถึง LSA ได้อีก
