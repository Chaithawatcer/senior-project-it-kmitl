---
threat_name: "Steal or Forge Authentication Certificates (Technique Defense Guide)"
technique_ids: ["T1649"]
severity: High
source_doc: "T1649_Technique_Defense_Guide_v1"
doc_type: defense
---

> เอกสารนี้คือ KB ส่วนที่ 2 ตามขอบเขต proposal §3.2 — "เอกสารแนวทางป้องกันรายเทคนิค"
> ต่างจาก threat playbook (`playbooks/*.md`) ตรงที่ไม่ผูกกับ threat scenario ใดโดยเฉพาะ
> เป็นแนวทางระดับ technique ล้วนๆ ใช้ประกอบกับ threat playbook เมื่อ alert ไม่ตรง threat
> เล่มไหนเป๊ะ แต่ technique ตรง (grounding tier "technique_composed" ตาม ARCHITECTURE.md §4)

> **หลักคิดหลักของเทคนิคนี้:** certificate ที่ AD CS ออกให้ใช้ยืนยันตัวตนได้ (PKINIT/Schannel)
> เหมือนรหัสผ่าน — และมัน**อายุยาว, ไม่ผูกกับการเปลี่ยนรหัส, MFA กันไม่ได้** ผู้โจมตีจึงได้ cert ที่
> auth เป็น user อื่นได้ 2 ทาง: (1) **abuse template/CA ที่ตั้งค่าพลาด** ให้ขอ cert สวมสิทธิ์คนอื่น
> (ESC1–ESC8) หรือ (2) **ขโมย private key ของ CA** แล้ว forge cert เองทั้งหมด (Golden Certificate)
> — การป้องกันจึงตัดที่ **การตั้งค่า template/CA**, **การปกป้อง CA key**, และ **การเฝ้าการออก/ใช้
> cert** ไม่ใช่ที่ชั้น login เพราะ cert เกิดหลังจุดนั้น

> **หมายเหตุการจัดหัวข้อ:** T1649 ใน MITRE ไม่มี sub-technique — ทุก section จึง tag `[T1649]`
> แต่แยกตามจุดตัด (scope/template/CA key/enrollment/monitoring) เพื่อให้ retrieval ดึง control
> ที่ตรงสถานการณ์ได้ (ARCHITECTURE.md §4.3–4.4)

## Phase: preparation
### Sub: adcs_baseline_and_template_review [T1649]
- ทำ **inventory CA, certificate template และ enrollment permission** ล่วงหน้า; ระบุ template ที่เสี่ยง (ESC1–ESC8 misconfig เช่น ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU) และตั้ง baseline การ issue cert ปกติ
- รู้ล่วงหน้าว่าใคร enroll cert ที่ authenticate ได้บ้าง เพื่อจับการออก cert ผิดปกติภายหลัง

### Sub: ca_key_protection_prep [T1649]
- ป้องกัน **CA private key ด้วย HSM**, จำกัด role CA administrator/certificate manager, และปิด web enrollment/NTLM relay ที่ไม่จำเป็น — forged cert ต้องอาศัย CA key หรือ template ที่ตั้งผิด

## Phase: detection_analysis
### Sub: certificate_issuance_detection [T1649]
- เฝ้า **Event 4886/4887 (cert request/issue) ที่ SAN ไม่ตรงกับ requester** และการ enroll cert ที่ให้ client-authentication โดยบัญชีที่ไม่ควร, รวมถึงการใช้ cert เพื่อ authenticate (**Event 4768 PKINIT**)
- ยืนยันขอบเขต: cert/template/บัญชีที่เกี่ยวข้องและ CA ที่ออก

### Sub: ca_abuse_detection [T1649]
- เฝ้า **การเข้าถึง CA private key**, การเปลี่ยน template ACL/setting, และ enrollment ที่ผิด baseline (ปริมาณ/ประเภท/เวลา)

## Phase: containment
### Sub: scope_and_isolate [T1649]
- **แยกให้ออกว่าเป็น key theft หรือ template abuse**: ถ้าสงสัย **CA private key ถูกขโมย** (Golden Certificate) ให้ถือว่าผู้โจมตี forge cert เป็นใครก็ได้ = domain-wide เทียบเท่า Golden Ticket; ถ้าเป็นการ **abuse template** (ESC1–8) blast radius จำกัดที่ template/สิทธิ์นั้น — contain ตามระดับ
- **ตัด follow-on**: cert ที่ได้จะถูกใช้ auth ต่อ (PKINIT ขอ TGT, Schannel) → เพิกถอน session/ticket ที่ออกให้ identity ที่ถูกสวม และระงับบัญชีเป้าหมายที่ถูกปลอม
- เก็บหลักฐาน **CA issuance log (Event 4886/4887), ใบ cert ที่ออกผิดปกติ, template ACL** ก่อนแก้ค่า

### Sub: revoke_and_deny_enrollment [T1649]
- **เพิกถอน (revoke) certificate ที่ถูกออกโดยมิชอบ** และปิด/จำกัด template ที่ถูก abuse ชั่วคราว — ระวังว่า **revocation อาจไม่หยุด PKINIT ทันที** ถ้า DC ไม่เช็ค CRL เข้ม จึงควรตัดที่ template/enrollment ควบคู่
- ถ้าสงสัย CA key รั่ว ให้ **ระงับการออก cert จาก CA ที่กระทบ** ชั่วคราวจนกว่าจะประเมินเสร็จ

## Phase: eradication
### Sub: template_hardening [T1649]
- **แก้ template ที่เปิดช่อง ESC1–ESC4**: ปิดคอมโบอันตราย "ผู้ขอระบุ subject/SAN ได้เอง (ENROLLEE_SUPPLIES_SUBJECT)" + EKU ที่ auth ได้ (Client Authentication/Smart Card Logon), บังคับ **manager approval**, และลบสิทธิ์ enroll ที่กว้างเกิน (Authenticated Users/Domain Users)
- ปิดค่า **EDITF_ATTRIBUTESUBJECTALTNAME2 ที่ CA (ESC6)** และตรวจ template ACL ที่เขียนได้โดย low-priv (ESC4) — พวกนี้ให้สวม SAN เป็น domain admin ได้

### Sub: ca_key_and_role_protection [T1649]
- **ปกป้อง CA private key ด้วย HSM** และจำกัด **สิทธิ์ CA administrator/Manage CA (ESC7)** ให้เหลือเฉพาะที่จำเป็น — CA key คือของที่ถ้าหลุดแล้ว forge ได้ทุกอย่าง
- ถ้ายืนยันว่า **CA key ถูกขโมย**: ต้อง **reissue CA และ re-enroll cert ทั้งระบบ** (งานใหญ่) เพราะ revoke ใบเดียวไม่พอ — cert ที่ forge จาก key เดิมยังใช้ได้จนกว่าจะเลิกเชื่อ CA เดิม

### Sub: enrollment_and_relay_hardening [T1649]
- **จำกัดสิทธิ์ enrollment agent (ESC3)** และ certificate ที่มี EKU "Certificate Request Agent"
- **กัน NTLM relay ไปยัง AD CS HTTP/Web Enrollment (ESC8)**: ปิด web enrollment ที่ไม่ใช้, บังคับ HTTPS + Extended Protection for Authentication (EPA), และปิด NTLM ที่ endpoint เหล่านั้น

## Phase: recovery
### Sub: issuance_monitoring_baseline [T1649]
- ตั้ง **monitoring การออก cert ที่ CA** (Event 4886/4887) และ alert เมื่อมี cert ที่ **SAN ไม่ตรงกับผู้ขอ**, ออกให้บัญชีอื่น, หรือมี EKU auth บน template ที่ไม่ควรมี
- เฝ้า **การใช้ cert เพื่อ auth** (Event 4768 แบบ certificate-based / PKINIT) ที่ผิดรูปจาก baseline

### Sub: adcs_audit_and_least_privilege [T1649]
- ทำ **audit ค่า template/CA เป็นรอบ** ด้วยมุมมอง ESC1–8 (เครื่องมือแนว Certify/Locksmith) — ปิดช่องที่ค่อยๆ ย้อนกลับมาจากการเปลี่ยน config
- ตั้ง **least-privilege บนสิทธิ์ enroll/manage template และ CA role** เป็น baseline และทบทวนเมื่อมีการเพิ่ม template ใหม่
