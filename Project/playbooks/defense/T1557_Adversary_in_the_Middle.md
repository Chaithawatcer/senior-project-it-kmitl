---
threat_name: "Adversary-in-the-Middle (Technique Defense Guide)"
technique_ids: ["T1557", "T1557.001"]
severity: High
source_doc: "T1557_Technique_Defense_Guide_v1"
doc_type: defense
---

> เอกสารนี้คือ KB ส่วนที่ 2 ตามขอบเขต proposal §3.2 — "เอกสารแนวทางป้องกันรายเทคนิค"
> ต่างจาก threat playbook (`playbooks/*.md`) ตรงที่ไม่ผูกกับ threat scenario ใดโดยเฉพาะ
> เป็นแนวทางระดับ technique ล้วนๆ ใช้ประกอบกับ threat playbook เมื่อ alert ไม่ตรง threat
> เล่มไหนเป๊ะ แต่ technique ตรง (grounding tier "technique_composed" ตาม ARCHITECTURE.md §4)

> **หลักคิดหลักของเทคนิคนี้:** AiTM อาศัยช่องที่ protocol เครือข่ายพื้นฐาน (ARP, LLMNR/NBT-NS,
> DHCP) ไม่มี authentication มาแต่เดิม ผู้โจมตีจึงแทรกตัวเป็นทางผ่านของทราฟฟิกได้ — จะ "patch"
> ตัว protocol ตรงๆ ไม่ได้ การป้องกันจึงเป็น 4 ชั้น: (1) **ปิด/ถอด** protocol ที่ไม่จำเป็น
> (2) **เซ็น/เข้ารหัส** ทราฟฟิกให้ดักไปก็ใช้ไม่ได้ (3) **บังคับที่ switch/infra**
> (4) **segment** ให้ position AiTM เอื้อมถึงน้อยลง — และ position เป็นแค่จุดตั้งต้น เป้าหมายจริง
> คือ sniff/relay/แก้ทราฟฟิกที่ตามมา ต้องกันที่ payoff นั้นด้วย

> **หมายเหตุการจัดหัวข้อ:** section ที่ tag `[T1557]` คือ control ระดับครอบทั้งเทคนิค (ใช้ได้ทุก
> variant ของ AiTM) ส่วน `[T1557.001]` คือ control เจาะจงของ variant name-service poisoning +
> NTLM relay (LLMNR/NBT-NS) — โครงนี้ช่วยให้ retrieval ดึงได้ถูกชั้น ไม่ว่า alert จะ map มาที่
> base technique หรือลงลึกถึง sub (ARCHITECTURE.md §4.3–4.4)

## Phase: preparation
### Sub: network_auth_baseline [T1557]
- **map protocol ที่ใช้ name resolution** (LLMNR, NBT-NS, mDNS) และ SMB/LDAP signing posture ล่วงหน้า — ระบุ segment ที่ยังเปิด broadcast resolution เป็นความเสี่ยง AitM
- จัดทำ baseline ว่า host ใดควรตอบ name query ได้ (DNS server จริง) เพื่อจับ rogue responder ภายหลัง

### Sub: disable_legacy_resolution_prep [T1557.001]
- เตรียม **GPO ปิด LLMNR/NBT-NS**, บังคับ **SMB signing** และ **LDAP channel binding/signing** เป็น baseline เชิงป้องกัน — ปิดทั้งช่อง poisoning และ NTLM relay ก่อนเกิดเหตุ

## Phase: detection_analysis
### Sub: poisoning_detection [T1557.001]
- เฝ้า **LLMNR/NBT-NS response ที่มาจาก host ที่ไม่ใช่ DNS server ปกติ** และการตอบ name query จำนวนมากจาก host เดียว (Responder pattern) — เทียบกับ baseline name-service
- ยืนยันขอบเขต: host ที่เป็น rogue responder และ client ที่หลงเชื่อ

### Sub: relay_detection [T1557]
- เฝ้า **NTLM authentication ที่ relay ข้าม host** (source/destination ผิดปกติ) และ inbound SMB signing failure ที่เพิ่มขึ้นผิดปกติ

## Phase: containment
### Sub: isolate_and_scope [T1557]
- ระบุ **ขอบเขต L2/segment ที่ถูกยึด position**: AiTM ส่วนใหญ่จำกัดอยู่ใน broadcast domain/VLAN เดียว — isolate host/switch port ที่ทำตัวเป็น rogue (ตอบ ARP/DHCP/name query แทนเครื่องจริง) ออกจาก segment ก่อน แล้วค่อยไล่ว่าเป็น variant ไหน
- **ตัด follow-on ที่เป็นเป้าหมายจริง**: position เป็นแค่จุดตั้งต้น สิ่งที่ต้องกันคือ Network Sniffing / relay / data manipulation ที่ตามมา — บังคับ encrypted protocol บนเส้นทางสำคัญ และ revoke credential/session ที่อาจถูกดักไประหว่างนั้น
- เก็บ **หลักฐานระดับ network ทันที** (ARP table, switch MAC/CAM table, DHCP lease, packet capture) ก่อน remediate — state ของ AiTM อยู่ชั่วคราวในอุปกรณ์เครือข่าย หายง่ายหลัง reboot/clear

### Sub: disable_name_services [T1557.001]
- **ปิด LLMNR, NBT-NS และ mDNS** ผ่าน Group Policy/registry ทันทีทั่ว fleet (M1042) — ตัดช่องที่ Responder ใช้ตอบ name query ปลอม เป็น containment ที่ตรงจุดสุดของ variant นี้
- ระบุและ isolate เครื่องที่รัน poisoner — host เดียวที่ตอบ LLMNR/NBT-NS หลาย name ผิดปกติ หรือ claim ตัวเป็นหลาย service

## Phase: eradication
### Sub: enforce_signing_encryption [T1557]
- **บังคับ signing/encryption ที่ปลายทาง** เพื่อทำให้ position AiTM ไร้ค่า: SMB signing, LDAP signing + channel binding, และบังคับ protocol ที่เข้ารหัส (HTTPS/LDAPS/SMB3 encryption) แทน cleartext (M1041) — ดักได้ก็อ่าน/relay ไม่ได้
- **จำกัด/ถอน credential ที่อาจรั่วผ่าน AiTM** และตรวจว่าไม่มี service ยังส่ง credential แบบ cleartext บน segment (legacy protocol, basic auth ภายใน)
- แก้ที่ **ชั้น infrastructure**: ยืนยันว่าไม่มี rogue device/VM หลงเหลือใน segment และ control ที่ switch/infra ถูกเปิดจริง ไม่ใช่แค่ตั้งค่าไว้

### Sub: break_ntlm_relay [T1557.001]
- **บังคับ SMB signing (required) ทั้ง client และ server** + เปิด EPA (Extended Protection for Authentication) และ LDAP channel binding — ตัด NTLM relay ที่เป็น payoff จริงของ variant นี้ ให้ hash ที่ดักได้ relay ต่อไม่ได้
- **จำกัด/ปิด NTLM เท่าที่ทำได้** (บังคับ Kerberos) และไล่ปิด service ที่ยัง fallback ไป NTLM — ปิดต้นตอที่ทำให้ relay มีของให้เล่น

## Phase: recovery
### Sub: segment_and_monitor [T1557]
- ทำ **network segmentation / least access** (M1030, M1035): ลดขนาด broadcast domain และจำกัดว่าใครคุยกับ critical host ได้ เพื่อให้ position AiTM ครั้งหน้าเอื้อมถึงแคบลง
- ตั้ง **monitoring ระดับ L2/L3 เป็น baseline**: เฝ้า ARP anomaly, การเปลี่ยน MAC–IP binding, rogue DHCP และ multiple-response ต่อ name query — ส่งเข้า SIEM ต่อเนื่อง ไม่ใช่แค่ตอนมี incident
- คืน config ที่ตั้งเข้มชั่วคราวสู่ระดับใช้งานจริง แต่ไม่ถอย baseline security จนเปิดช่องเดิม

### Sub: verify_name_service_lockdown [T1557.001]
- Audit ยืนยันว่า **LLMNR/NBT-NS/mDNS ถูกปิดถาวรทั้ง fleet** และ SMB/LDAP signing เป็น baseline — ไม่ใช่แก้เฉพาะเครื่องที่โดน
- ตั้ง detection: name query ที่ถูกตอบจาก non-authoritative source และ NTLM authentication ที่ปลายทาง/ต้นทางผิดรูป (relay pattern)