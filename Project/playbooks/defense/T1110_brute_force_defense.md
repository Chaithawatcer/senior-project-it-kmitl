---
threat_name: "Brute Force (Technique Defense Guide)"
technique_ids: ["T1110", "T1110.001", "T1110.003"]
severity: Medium
source_doc: "T1110_Technique_Defense_Guide_v1"
doc_type: defense
---

> เอกสารนี้คือ KB ส่วนที่ 2 ตามขอบเขต proposal §3.2 — "เอกสารแนวทางป้องกันรายเทคนิค"
> ต่างจาก threat playbook (`playbooks/*.md`) ตรงที่ไม่ผูกกับ threat scenario ใดโดยเฉพาะ
> เป็นแนวทางระดับ technique ล้วนๆ ใช้ประกอบกับ threat playbook เมื่อ alert ไม่ตรง threat
> เล่มไหนเป๊ะ แต่ technique ตรง (grounding tier "technique_composed" ตาม ARCHITECTURE.md §4)

## Phase: containment
### Sub: rate_limiting [T1110.001]
- ตั้ง **rate limiting ที่ authentication endpoint**: จำกัดจำนวน attempt ต่อ IP ต่อบัญชีในหน้าต่างเวลาสั้น (เช่น 5 ครั้ง/นาที) ก่อนจะ throttle หรือปฏิเสธ
- เปิด **CAPTCHA แบบ adaptive**: บังคับเฉพาะเมื่อ IP/บัญชีเริ่มมีพฤติกรรมผิดปกติ ไม่บังคับทุกครั้งเพื่อไม่กระทบ UX ปกติ
- **บล็อกที่ระดับ edge** (firewall/WAF/reverse proxy) ไม่ใช่แค่ระดับ application — กัน load ไม่ให้ถึง backend ด้วย

### Sub: rate_limiting_spray [T1110.003]
- ตรวจจับ **breadth-based pattern**: จำนวนบัญชีที่ถูกลองจาก IP เดียวสูงผิดปกติ แม้ความถี่ต่อบัญชีจะต่ำ (หลบ per-account rate limit ได้ แต่หลบ per-IP ไม่ได้)
- ตั้ง threshold แยกสำหรับ **จำนวนบัญชี distinct ต่อ IP ต่อชั่วโมง** ไม่ใช่แค่จำนวนครั้งต่อบัญชี

## Phase: eradication
### Sub: credential_hygiene [T1110.001]
- บังคับ **เปลี่ยนรหัสผ่านที่ตรวจพบว่าอ่อนแอ** หรือซ้ำกับ known-breached password list (ตรวจผ่าน HaveIBeenPwned API แบบ k-anonymity)
- ลบ **บัญชีทดสอบ/บัญชี default** ที่มักถูกใช้เป็นเป้า (admin, test, guest) ถ้าไม่จำเป็นต้องมี

### Sub: mfa_rollout [T1110.003]
- Deploy **MFA แบบ risk-based**: บังคับ MFA เมื่อ login จาก IP/device/ตำแหน่งใหม่ แทนที่จะบังคับทุกครั้ง (ลด friction แต่ยังปิดช่องโหว่หลักของ credential-only auth)
- ตรวจสอบว่า **MFA ครอบคลุมทุกช่องทางเข้าจริง** ไม่ใช่แค่ web login (เช่น legacy protocol อย่าง IMAP/POP3/SMTP AUTH ที่มักไม่รองรับ MFA และกลายเป็นช่องหลบ)

## Phase: recovery
### Sub: baseline_restoration [T1110.001]
- คืนค่า **rate limit/CAPTCHA settings** กลับสู่ระดับปกติหลังยืนยันว่าการโจมตีหยุดแล้ว ไม่ปล่อยให้ threshold เข้มเกินไปถาวรจนกระทบผู้ใช้จริง
- ปรับ **baseline การตรวจจับ** (เช่น threshold ของ SIEM rule) ให้สะท้อนรูปแบบการโจมตีที่เพิ่งเจอ สำหรับตรวจจับเร็วขึ้นในครั้งถัดไป

### Sub: monitoring_handoff [T1110.003]
- ส่งต่อ **IP/pattern ที่เพิ่งเจอ** เข้าสู่ threat intelligence feed ภายในองค์กร (allowlist/blocklist) เพื่อประโยชน์ข้าม incident
- ยืนยันว่า **dashboard เฝ้าระวัง** แสดงอัตราการ login ล้มเหลวแบบ real-time ต่อเนื่อง ไม่ใช่แค่ตอนมี incident
