---
threat_name: "Steal or Forge Kerberos Tickets (Technique Defense Guide)"
technique_ids: ["T1558", "T1558.001", "T1558.002", "T1558.003", "T1558.004"]
severity: High
source_doc: "T1558_Technique_Defense_Guide_v1"
doc_type: defense
---

> เอกสารนี้คือ KB ส่วนที่ 2 ตามขอบเขต proposal §3.2 — "เอกสารแนวทางป้องกันรายเทคนิค"
> ต่างจาก threat playbook (`playbooks/*.md`) ตรงที่ไม่ผูกกับ threat scenario ใดโดยเฉพาะ
> เป็นแนวทางระดับ technique ล้วนๆ ใช้ประกอบกับ threat playbook เมื่อ alert ไม่ตรง threat
> เล่มไหนเป๊ะ แต่ technique ตรง (grounding tier "technique_composed" ตาม ARCHITECTURE.md §4)

> **หลักคิดหลักของเทคนิคนี้:** Kerberos วางความเชื่อไว้บนความลับของ **key ที่ใช้เซ็น ticket** —
> krbtgt hash (เซ็น TGT) และ service account hash (เซ็น TGS) ถ้าผู้โจมตีได้ key เหล่านี้ หรือขอ
> ticket ที่เข้ารหัสอ่อน (RC4) ไปแครกออฟไลน์สำเร็จ ก็ **forge/ปลอม ticket เป็น identity ใดก็ได้
> โดยไม่ต้องรู้รหัสผ่าน และ MFA กันไม่ได้** เพราะเป็นขั้นหลัง authenticate — การป้องกันจึงตัดที่
> 3 จุด: (1) **ความแข็งแรงของ key** (krbtgt/service account password, บังคับ AES ปิด RC4)
> (2) **ลดของให้ขโมย/แครก** (least-privilege SPN, gMSA, บังคับ pre-auth) (3) **เฝ้าพฤติกรรม
> การออก/ใช้ ticket** ที่ผิดปกติ — และ follow-on จริงคือ Use Alternate Authentication Material
> (T1550) ที่เอา ticket ปลอมไปใช้ต่อ ต้องกันที่ payoff นั้นด้วย

> **หมายเหตุการจัดหัวข้อ:** section ที่ tag `[T1558]` คือ control ระดับครอบทั้งเทคนิค (ใช้ได้ทุก
> variant) ส่วน `[T1558.00x]` คือ control เจาะจงตามชนิด ticket ที่ถูกปลอม/ขโมย เพราะ key ที่ต้อง
> ปกป้องต่างกัน (krbtgt / service account / pre-auth) — โครงนี้ช่วยให้ retrieval ดึงได้ถูกชั้น ไม่ว่า
> alert จะ map มาที่ base technique หรือลงลึกถึง sub (ARCHITECTURE.md §4.3–4.4)

## Phase: preparation
### Sub: kerberos_hardening_baseline [T1558]
- จัดทำ **inventory service account ที่มี SPN** และตั้ง baseline อายุ/rotation ของ **krbtgt**; เปิด **AES และปิด RC4** ล่วงหน้า — ลดพื้นผิวทั้ง roasting และ forged ticket
- รู้ล่วงหน้าว่า TGT/TGS lifetime ปกติเป็นเท่าใด เพื่อจับ ticket อายุยาวผิดปกติภายหลัง

### Sub: krbtgt_and_privileged_prep [T1558.001]
- ทำ **krbtgt password rotation ตามรอบ (double reset)** เชิงป้องกัน และจำกัดสิทธิ์ที่เข้าถึง krbtgt hash — golden ticket ต้องใช้ krbtgt key

### Sub: service_account_prep [T1558.002, T1558.003]
- ใช้ **gMSA หรือรหัสยาวสุ่ม** สำหรับ service account และลด SPN ที่ไม่จำเป็น — silver ticket และ kerberoast อาศัย service-account key ที่อ่อน

### Sub: preauth_prep [T1558.004]
- **บังคับ Kerberos pre-authentication ทุกบัญชี** (ปิด DONT_REQUIRE_PREAUTH) เชิงป้องกัน AS-REP roasting

## Phase: detection_analysis
### Sub: ticket_anomaly_detection [T1558.001, T1558.002]
- เฝ้า **TGT/TGS อายุยาวผิดปกติ** และ **encryption downgrade เป็น RC4** ใน Event 4769 (ticket options/etype ผิด baseline), รวมถึง TGS ของ service ที่ไม่ควรถูกร้องขอ
- ยืนยันขอบเขต: บัญชี/service ที่เกี่ยวข้องและ DC ที่ออก ticket

### Sub: kerberoast_detection [T1558.003]
- เฝ้า **Event 4769 ที่ขอ TGS จำนวนมากด้วย RC4 (0x17)** จากบัญชีเดียวในเวลาสั้น (pattern การ roast service ticket)

### Sub: asrep_roast_detection [T1558.004]
- เฝ้า **Event 4768 (AS-REQ) ที่ไม่มี pre-auth** จากบัญชีที่ตั้ง DONT_REQUIRE_PREAUTH

## Phase: containment
### Sub: scope_and_isolate [T1558]
- ระบุ **ขอบเขตว่าถูกแตะ key ระดับไหน**: ถ้าสงสัย krbtgt หรือ DC ถูกยึด ถือเป็น domain-wide (Golden Ticket forge ได้ทุกบัญชี) — ต่างจากกรณี service account เดียวรั่วที่ blast radius แคบกว่า ให้ contain ตามระดับที่ scope ได้
- **ตัด follow-on ที่เป็นเป้าหมายจริง**: ticket ที่ขโมย/ปลอมจะถูกเอาไปใช้ต่อเป็น Use Alternate Authentication Material (T1550) — ระงับ/ลดสิทธิ์บัญชี-บทบาทที่ ticket กำลังเข้าถึง และ revoke session ที่ปลายทาง ไม่ใช่รอแค่ล้าง ticket
- เก็บ **หลักฐานฝั่ง KDC ทันที** (Event 4768/4769/4770, encryption type ที่ขอ, DC security log, memory ของ host ที่สงสัย) ก่อน reset key — forged ticket ที่ออกไปแล้วยังใช้ได้จนกว่าจะหมุน key ต้นทาง

### Sub: golden_ticket_containment [T1558.001]
- **แยก DC และเตรียม reset krbtgt** ถ้าสงสัยว่า krbtgt hash รั่ว: Golden Ticket คือ TGT ที่ผู้โจมตีเซ็นเองด้วย krbtgt hash อายุยาว (มักตั้ง 10 ปี) — ตราบใดที่ยังไม่หมุน krbtgt ticket ปลอมทั้งหมดยังใช้ได้ ไม่มีทาง revoke ทีละใบ
- ระงับ/รีเซ็ตบัญชี privileged ที่ถูกอ้างใน ticket ที่ผิดปกติ และตัดเส้นทางที่ผู้โจมตีใช้ดึง krbtgt (DCSync / เข้าถึง NTDS.dit / LSASS บน DC)

### Sub: silver_ticket_containment [T1558.002]
- **หมุนรหัสผ่าน service account เป้าหมายทันที**: Silver Ticket คือ TGS ปลอมที่เซ็นด้วย hash ของ service account (หรือ computer account) นั้นๆ — เปลี่ยนรหัสแล้ว TGS ปลอมของ service นั้นใช้การไม่ได้
- ระวังว่า Silver Ticket **ไม่คุยกับ DC** (ข้ามการขอ TGS) — จะไม่มี Event 4769 ให้เห็น ต้อง scope ที่ log ของตัว service/host ปลายทางเป็นหลัก

### Sub: roasting_containment [T1558.003, T1558.004]
- ระบุบัญชีที่ **hash ถูกดึงไปแครกออฟไลน์** (Kerberoasting = ขอ TGS ของบัญชีที่มี SPN, AS-REP Roasting = บัญชีที่ปิด pre-auth) — ถือว่ารหัสผ่านบัญชีเหล่านั้นกำลังจะหลุด บังคับ **reset รหัสทันที** และ lock บัญชีที่ไม่จำเป็นต้องใช้
- ตัด SPN ออกจากบัญชีที่ไม่ควรมี และปิดสิทธิ์ที่บัญชีเป้าหมายเข้าถึงได้ระหว่างรอ reset — ลดมูลค่าของ hash ที่กำลังถูกแครก

## Phase: eradication
### Sub: kerberos_key_hygiene [T1558]
- **บังคับ AES และปิด RC4/DES ทั้งโดเมน** (M1015): ticket ที่เข้ารหัส RC4 แครกออฟไลน์ได้เร็วกว่ามาก — บังคับ AES ตัดทั้ง Kerberoasting และ forge ที่อาศัย RC4 ที่ต้นทาง
- **Audit สิทธิ์ที่เข้าถึง DC / krbtgt / NTDS.dit ได้** (M1043, M1026): ปิดช่องที่ผู้โจมตีใช้ดึง key (DCSync สิทธิ์ replication, local admin บน DC) แล้วลดสิทธิ์ให้เหลือเท่าที่จำเป็น — ถ้าไม่ปิดต้นตอ จะถูก forge ซ้ำแม้หมุน key แล้ว
- ย้ายบัญชี privileged เข้า **Protected Users group** และจำกัด delegation (โดยเฉพาะ unconstrained) ที่เปิดทางให้ยึด TGT

### Sub: krbtgt_double_reset [T1558.001]
- **reset รหัสผ่าน krbtgt สองครั้ง** โดยเว้นให้ replication เสร็จระหว่างสองรอบ — krbtgt เก็บทั้งรหัสปัจจุบันและก่อนหน้า ถ้า reset รอบเดียว Golden Ticket ที่เซ็นด้วยรหัสก่อนหน้ายังใช้ได้ ต้องสองรอบถึงจะล้างของเก่าจริง
- reset รหัสบัญชี privileged อื่นที่อาจถูก compromise ร่วม และตรวจว่าไม่มี ticket อายุยาวผิดปกติหลงเหลือหลังหมุน

### Sub: service_account_hardening [T1558.002]
- **หมุนรหัส service account ที่ถูกใช้ปลอม TGS** และย้ายไปใช้ **gMSA** ที่หมุนรหัสอัตโนมัติและยาวจนแครกไม่ไหว — ตัดทั้ง Silver Ticket และการ crack ของ variant นี้ที่ต้นเหตุ
- ตรวจ **computer account / service ที่ตั้งรหัสอ่อนหรือไม่เคยหมุน** โดยเฉพาะบัญชีสิทธิ์สูง เพราะ hash ของมันเซ็น TGS ได้โดยตรง

### Sub: kerberoast_hardening [T1558.003]
- บังคับ **รหัสผ่านยาว (25+ ตัว) หรือ gMSA สำหรับทุกบัญชีที่มี SPN** (M1027) — TGS ที่ขอมาแครกไม่คุ้มถ้ารหัสยาวและเป็น AES
- **ลบ SPN ที่ไม่จำเป็น** และตั้ง service account เป็น least-privilege (M1018): ยิ่งบัญชี SPN มีสิทธิ์สูงและรหัสอ่อน ยิ่งเป็นเป้า Kerberoasting คุ้มค่า

### Sub: enforce_preauth [T1558.004]
- **บังคับ Kerberos pre-authentication ทุกบัญชี** (ปิด "Do not require Kerberos preauthentication") — เป็นเงื่อนไขเดียวที่เปิดทาง AS-REP Roasting ถ้าปิดช่องนี้ variant นี้ทำไม่ได้เลย
- ตรวจ audit หา account ที่ตั้ง flag นี้ค้างไว้เป็นรอบ และบังคับรหัสผ่านแข็งแรงกับบัญชีที่เคยเปิด (เผื่อ AS-REP หลุดไปแล้ว)

## Phase: recovery
### Sub: ticket_monitoring_baseline [T1558]
- ตั้ง **monitoring การออก/ใช้ ticket เป็น baseline**: เฝ้า Event 4768 (AS-REQ), 4769 (TGS-REQ), 4770 (renew) และตั้ง alert บน **การขอ ticket ที่เข้ารหัส RC4 (type 0x17)**, lifetime ที่ยาวผิดปกติ, และ ticket ที่อ้าง account ซึ่งไม่มีอยู่จริง — ส่งเข้า SIEM ต่อเนื่อง ไม่ใช่แค่ตอนมี incident
- คืน config ที่ตั้งเข้มชั่วคราวสู่ระดับใช้งานจริง แต่คง baseline (AES-only, pre-auth, gMSA) ไว้ ไม่ถอยจนเปิดช่องเดิม

### Sub: forged_ticket_detection [T1558.001, T1558.002]
- ตั้ง detection สำหรับ **ticket ที่ถูก forge**: TGT/TGS ที่ field ไม่สอดคล้อง (เช่น lifetime เกิน policy ของโดเมน, ใช้ TGS โดยไม่มี 4768 คู่กัน = สัญญาณ Silver Ticket ที่ข้าม DC), หรือ account ใน ticket ไม่ตรง SID/สิทธิ์จริง
- ยืนยัน **cadence การหมุน krbtgt และ service account key** เป็นรอบตาม policy และเก็บ baseline ของ privileged ticket ที่ถูกต้องไว้เทียบ (สำหรับ incident ครั้งถัดไป)

### Sub: roasting_detection [T1558.003, T1558.004]
- ตั้ง alert บน **การขอ TGS จำนวนมากจาก host เดียวด้วย RC4** (รูปแบบ Kerberoasting) และ **AS-REQ ที่ไม่มี pre-auth** (รูปแบบ AS-REP Roasting) — ตั้ง threshold เทียบ baseline ปกติของแต่ละ host/บัญชี
- ทบทวน **รายการบัญชี SPN และบัญชีที่ปิด pre-auth** เป็นรอบ เพื่อกันไม่ให้ config ที่เปิดช่อง roasting ย้อนกลับมาโดยไม่มีใครรู้
