---
threat_name: "Forge Web Credentials (Technique Defense Guide)"
technique_ids: ["T1606", "T1606.002"]
severity: High
source_doc: "T1606_Technique_Defense_Guide_v1"
doc_type: defense
---

> เอกสารนี้คือ KB ส่วนที่ 2 ตามขอบเขต proposal §3.2 — "เอกสารแนวทางป้องกันรายเทคนิค"
> ต่างจาก threat playbook (`playbooks/*.md`) ตรงที่ไม่ผูกกับ threat scenario ใดโดยเฉพาะ
> เป็นแนวทางระดับ technique ล้วนๆ ใช้ประกอบกับ threat playbook เมื่อ alert ไม่ตรง threat
> เล่มไหนเป๊ะ แต่ technique ตรง (grounding tier "technique_composed" ตาม ARCHITECTURE.md §4)

> **หลักคิดหลักของเทคนิคนี้:** credential ที่ถูก forge (SAML token/assertion) ถูกสร้างขึ้น
> *หลัง* ขั้น authenticate + MFA ในสายความเชื่อ ระบบปลายทางจึงมองว่า "ผ่านการยืนยันตัวตนแล้ว"
> MFA ปกติจึงกันไม่ได้ — การป้องกันต้องตัดที่ **ชั้น trust ของ token** (secret/cert ที่ใช้เซ็น)
> และที่ **พฤติกรรมการใช้ token** ไม่ใช่ที่ชั้น login

> **หมายเหตุการจัดหัวข้อ:** section ที่ tag `[T1606]` คือ control ระดับครอบทั้งเทคนิค ส่วน
> `[T1606.002]` คือ control ที่เจาะจงกับ variant SAML Tokens (Golden SAML) โดยตรง เพราะ
> ผูกกับ token-signing certificate ของ IdP — โครงนี้ช่วยให้ retrieval ดึงได้ถูกชั้น ไม่ว่า alert จะ map มาที่ base
> technique หรือลงลึกถึง sub ได้ (ARCHITECTURE.md §4.3–4.4)

## Phase: containment
### Sub: scope_and_blast_radius [T1606]
- ช่วงแรกมักยังไม่รู้ว่า assertion ถูก forge จากต้นทางใด — ให้ **contain ที่ชั้น trust ของ token ไว้ก่อน** จนกว่าจะ scope ได้ชัดว่า cert/secret ใดรั่ว แล้วค่อยตัดที่เจาะจง
- จำกัด blast radius ที่ **ตัวทรัพยากร** ไม่ใช่แค่ชั้น auth: ตัด/ลดสิทธิ์บัญชี-บทบาทที่ forged credential กำลังเข้าถึง เพราะ follow-on คือ Use Alternate Authentication Material (T1550) ที่เอา credential ปลอมไปใช้ต่อ
- เก็บ **หลักฐาน token/assertion ที่ผิดปกติ** (raw token, timestamp, ปลายทางที่ถูกเข้าถึง) ก่อนหมุน key/cert เพื่อไม่ให้หลักฐานหายและใช้ scope ผลกระทบต่อได้

### Sub: federation_isolation [T1606.002]
- **แยก/ระงับ AD FS server หรือ IdP ที่สงสัยว่า token-signing certificate รั่ว** ออกจากการออก token ชั่วคราว — Golden SAML ให้ผู้โจมตี forge assertion ของ user ใดก็ได้โดยไม่ต้องรู้รหัสผ่าน จึงต้องตัดที่ต้นทางการเซ็น
- **เพิกถอน session ฝั่ง relying party / cloud app** (revoke refresh token, force sign-out ทุก session ที่ IdP) — SAML assertion อายุสั้น แต่มักถูกแลกเป็น session ยาวที่ปลายทางไปแล้ว การ revoke cert อย่างเดียวไม่ตัด session ที่ออกไปก่อนหน้า
- ในคลาวด์: ระงับ/จำกัดสิทธิ์ที่ออก credential ได้เอง เช่น `sts:AssumeRole` / `sts:GetFederationToken` (AWS) สำหรับ principal ที่ไม่ควรมี — กันการต่ออายุการเข้าถึงระหว่างช่วง contain

## Phase: eradication
### Sub: secret_and_key_rotation [T1606]
- **หมุน secret material ทั้งชุดที่ forge ได้**: cookie signing/encryption key, JWT/OIDC signing key, API secret, ค่า seed ที่ deterministic — ครอบทุกแอปที่ใช้ key ร่วมกัน ไม่ใช่แค่ตัวที่ยิง alert
- ก่อนออก key ใหม่ ต้องหาให้เจอว่า **secret รั่วได้อย่างไร** (config leak, source code, memory/backup ที่เข้าถึงได้) แล้วปิดต้นตอก่อน ไม่งั้นจะถูก forge ซ้ำด้วย key ใหม่
- **Audit สิทธิ์เข้าถึง key store / secret manager** (M1047) — ตรวจว่าใครอ่าน secret ได้บ้าง แล้วลดสิทธิ์ให้เหลือเท่าที่จำเป็น

### Sub: saml_cert_reissue [T1606.002]
- **ออก token-signing certificate ใหม่และ revoke ใบเดิม** — สำหรับ AD FS ต้อง roll ใบ **สองรอบ** (primary + secondary) เพื่อล้างใบเก่าออกจากระบบจริง มิฉะนั้นใบเดิมยัง forge token ได้อยู่
- **Audit federation trust ทั้งหมด** (M1015): ลบ relying party trust / claims provider trust ที่ผู้โจมตีอาจตั้งขึ้นเอง และตรวจว่าไม่มี trust ชี้ไปยัง AD FS ปลอมของผู้โจมตี
- จำกัด **สิทธิ์ export certificate และสิทธิ์ตั้ง federation trust** ให้เหลือเฉพาะ admin ที่จำเป็น — ความสามารถนี้แหละที่เปลี่ยนการยึด host ธรรมดาให้กลายเป็น Golden SAML

## Phase: recovery
### Sub: access_audit [T1606]
- ทำ **audit สิทธิ์การเข้าถึง web app/service ทั้งหมด** และ review การใช้งาน token-signing certificate (M1047) — ตัด privilege ที่เกินจำเป็นทิ้ง เพื่อให้ credential ที่ถูก forge ในอนาคตมี blast radius เล็กลง
- ตั้ง **least-privilege เป็น baseline ใหม่** สำหรับบัญชี/บทบาทที่เข้าถึงทรัพยากรสำคัญ และทบทวนเป็นรอบ ไม่ใช่ครั้งเดียวจบ

### Sub: token_issuance_monitoring [T1606.002]
- เปิด/ยืนยัน **logging การออก token ที่ IdP** (AD FS / Entra ID sign-in + token issuance) และตั้ง detection บน **ความผิดปกติของการออก token** เช่น token ที่อ้างว่า authenticated แต่ไม่มี log การ login คู่กัน, lifetime ยาวผิดปกติ, หรือ claim/permission ที่แปลกไปจาก baseline
- ส่งต่อ **cert thumbprint และ federation trust config ที่ถูกต้อง** เข้าระบบเฝ้าระวัง เพื่อ alert เมื่อมีการเปลี่ยน token-signing certificate หรือเพิ่ม trust ในอนาคต (baseline สำหรับ incident ครั้งถัดไป)
- เสริม **conditional access / anomaly detection บนรูปแบบการใช้ token** ที่ปลายทาง (เช่น การใช้ token จากตำแหน่ง/เวลาที่ผิดปกติ) เพราะ MFA ปกติกันการใช้ token ที่ forge แล้วไม่ได้ — ต้องตรวจที่พฤติกรรม *หลัง* ออก token