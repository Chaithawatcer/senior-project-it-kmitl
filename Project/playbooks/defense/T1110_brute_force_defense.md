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

> **หมายเหตุการจัดหัวข้อ:** section ที่ tag `[T1110]` คือ control ระดับครอบทั้งเทคนิค (ใช้ได้ทั้ง
> depth = เดารหัสบัญชีเดียวรัวๆ และ breadth = สเปรย์รหัสเดียวหลายบัญชี) ส่วน `[T1110.001]`/
> `[T1110.003]` คือ control ที่เจาะจงตาม variant เพราะกลไกตรวจจับ/ป้องกันต่างกัน — โครงนี้ช่วยให้
> retrieval ดึงได้ถูกชั้น ไม่ว่า alert จะ map มาที่ base technique หรือลงลึกถึง sub (ARCHITECTURE.md §4.3–4.4)

## Phase: containment
### Sub: scope_and_lockout [T1110]
- ช่วงแรกให้ดู **ทั้งสองมิติพร้อมกัน** — depth (เดารหัสบัญชีเดียวรัวๆ, .001) และ breadth (รหัสเดียวหลายบัญชี, .003) — โดยเทียบ per-account attempt rate กับ distinct-account-per-IP ก่อนเลือกมาตรการเจาะจง เพราะ contain ผิดมิติจะพลาด (เช่นตั้ง per-account lockout อย่างเดียว หลบ spraying ได้)
- ใช้ **account lockout / temporary disable อย่างระวัง** (M1036): ปกป้องบัญชีเป้าหมายได้ แต่ lockout เหวี่ยงกว้างตอนโดนสเปรย์จะกลายเป็น self-DoS (ผู้โจมตี lock ผู้ใช้จริงยกแผง) — ควรตัดที่ IP/behavior ก่อนตัดที่บัญชี
- **ปกป้อง/ระงับบัญชี high-value ที่เป็นเป้าโดยตรงชั่วคราว** (admin, service account, ผู้บริหาร) และบังคับ reset ถ้าสงสัยว่าใกล้หลุด — จำกัด impact ระหว่างรอ scope ครบ

### Sub: rate_limiting [T1110.001]
- ตั้ง **rate limiting ที่ authentication endpoint**: จำกัดจำนวน attempt ต่อ IP ต่อบัญชีในหน้าต่างเวลาสั้น (เช่น 5 ครั้ง/นาที) ก่อนจะ throttle หรือปฏิเสธ
- เปิด **CAPTCHA แบบ adaptive**: บังคับเฉพาะเมื่อ IP/บัญชีเริ่มมีพฤติกรรมผิดปกติ ไม่บังคับทุกครั้งเพื่อไม่กระทบ UX ปกติ
- **บล็อกที่ระดับ edge** (firewall/WAF/reverse proxy) ไม่ใช่แค่ระดับ application — กัน load ไม่ให้ถึง backend ด้วย

### Sub: rate_limiting_spray [T1110.003]
- ตรวจจับ **breadth-based pattern**: จำนวนบัญชีที่ถูกลองจาก IP เดียวสูงผิดปกติ แม้ความถี่ต่อบัญชีจะต่ำ (หลบ per-account rate limit ได้ แต่หลบ per-IP ไม่ได้)
- ตั้ง threshold แยกสำหรับ **จำนวนบัญชี distinct ต่อ IP ต่อชั่วโมง** ไม่ใช่แค่จำนวนครั้งต่อบัญชี

## Phase: eradication
### Sub: account_cleanup [T1110]
- ล้าง **บัญชีที่ถูก compromise สำเร็จ** ไม่ว่าจะมาจากการเดาหรือสเปรย์: reset credential, เพิกถอน session/token ที่ออกหลัง login สำเร็จ, ตรวจ persistence ที่ผู้โจมตีอาจฝังหลังเข้าได้ — ปลายทางที่ต้องล้างคือ "บัญชีที่หลุด" เหมือนกันทั้งสอง variant
- บังคับ **password policy ที่แข็งแรงทั้งองค์กร** (M1027): min length/complexity + แบน common & breached password list — ปิดเงื่อนไขที่ทำให้ทั้งการเดาและสเปรย์สำเร็จตั้งแต่ต้นทาง

### Sub: credential_hygiene [T1110.001]
- บังคับ **เปลี่ยนรหัสผ่านที่ตรวจพบว่าอ่อนแอ** หรือซ้ำกับ known-breached password list (ตรวจผ่าน HaveIBeenPwned API แบบ k-anonymity)
- ลบ **บัญชีทดสอบ/บัญชี default** ที่มักถูกใช้เป็นเป้า (admin, test, guest) ถ้าไม่จำเป็นต้องมี

### Sub: mfa_rollout [T1110.003]
- Deploy **MFA แบบ risk-based**: บังคับ MFA เมื่อ login จาก IP/device/ตำแหน่งใหม่ แทนที่จะบังคับทุกครั้ง (ลด friction แต่ยังปิดช่องโหว่หลักของ credential-only auth)
- ตรวจสอบว่า **MFA ครอบคลุมทุกช่องทางเข้าจริง** ไม่ใช่แค่ web login (เช่น legacy protocol อย่าง IMAP/POP3/SMTP AUTH ที่มักไม่รองรับ MFA และกลายเป็นช่องหลบ)

## Phase: recovery
### Sub: policy_baseline [T1110]
- ตั้ง **account use & lockout policy เป็น baseline** (M1036) ที่กัน brute force ทั่วไปได้ทั้ง depth และ breadth — คืน threshold ที่ตั้งเข้มชั่วคราวกลับสู่ระดับใช้งานจริง แต่ไม่ถอย policy จนเปิดช่องเดิม
- ทำ **user account management / cleanup** (M1018): ปิดบัญชีที่ไม่ใช้, ทบทวนบัญชี privileged และบัญชี default/test ที่เป็นเป้าง่าย — ลด attack surface สำหรับ brute force รอบหน้าไม่ว่ารูปแบบใด

### Sub: baseline_restoration [T1110.001]
- คืนค่า **rate limit/CAPTCHA settings** กลับสู่ระดับปกติหลังยืนยันว่าการโจมตีหยุดแล้ว ไม่ปล่อยให้ threshold เข้มเกินไปถาวรจนกระทบผู้ใช้จริง
- ปรับ **baseline การตรวจจับ** (เช่น threshold ของ SIEM rule) ให้สะท้อนรูปแบบการโจมตีที่เพิ่งเจอ สำหรับตรวจจับเร็วขึ้นในครั้งถัดไป

### Sub: monitoring_handoff [T1110.003]
- ส่งต่อ **IP/pattern ที่เพิ่งเจอ** เข้าสู่ threat intelligence feed ภายในองค์กร (allowlist/blocklist) เพื่อประโยชน์ข้าม incident
- ยืนยันว่า **dashboard เฝ้าระวัง** แสดงอัตราการ login ล้มเหลวแบบ real-time ต่อเนื่อง ไม่ใช่แค่ตอนมี incident