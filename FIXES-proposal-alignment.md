# แก้อะไรไปบ้าง — จัด RAG-Core ให้ตรงกับ Proposal + ARCHITECTURE.md

> รอบรีวิวนี้เทียบโค้ดจริงบนบรานช์ `RAG-Core` กับ 2 เอกสารต้นทาง (proposal ที่เสนออาจารย์ + `ARCHITECTURE.md`)
> แล้วแก้จุดที่เบี่ยงไป 4 เรื่องใหญ่ ด้านล่างคือรายละเอียดของแต่ละเรื่อง — ทดสอบแล้วทุกจุด ไม่ใช่แค่เขียนแล้วเดา
>
> commit: `Align RAG-Core with proposal + ARCHITECTURE.md` (อยู่ในเครื่องแล้ว **ยังไม่ push**)

---

## 1. Phase ของ playbook: 5 (NIST) → 3 (proposal)

**ปัญหา:** โค้ดใช้ 5 phase ตาม NIST lifecycle (`preparation`, `detection`, `containment`, `eradication`, `post_incident`) แต่ proposal §3.3 และไฟล์ Quick Win ของอาจารย์ระบุตรงกัน **แค่ 3 phase**: Containment / Eradication / Recovery

**แก้ที่ไหน:**
- `Project/api.py` — `SECTIONS` ตัดเหลือ 3 รายการ (`containment`, `eradication`, `recovery`) พร้อม `fill_instruction` ใหม่ที่อ้างอิงคำจากไฟล์ Quick Win
- `Project/playbooks/01_brute_force.md`, `02_credential_dumping.md`, `03_rdp_bruteforce.md` — restructure ทั้ง 3 ไฟล์:
  - เนื้อหา Preparation/Detection เดิม **ไม่ได้ถูกลบ** — ย้ายไปเป็นบล็อก `## เอกสารอ้างอิง — Preparation, Detection & Post-Incident Review` ที่หัวไฟล์ (อยู่นอก `## Phase:` จึงไม่ถูก ingest แต่ยังอ่านอ้างอิงได้)
  - เนื้อหา `post_incident` (lessons learned/improvements) ก็ย้ายไปอยู่ในบล็อกอ้างอิงเดียวกัน
  - เขียนเนื้อหา **Recovery ใหม่ทั้งหมด** (3 sub-chunk ต่อไฟล์: service_restoration, validation_monitoring, closure) — ไม่ใช่แค่เปลี่ยนชื่อ phase เดิม เพราะ "Recovery" (คืนระบบให้ใช้งานได้ปกติ) กับ "Post-Incident" (ถอดบทเรียน) เป็นคนละเรื่องกัน

**ตรวจสอบแล้ว:** รัน `01_ingest.py` ใหม่ → 27 chunks จาก 3 playbook ครบ 3 phase (9 chunks/phase) ไม่มี phase เก่าหลงเหลือ

---

## 2. Mock Alert: SSH/Linux → Windows AD Event 4625/4740

**ปัญหา:** node `Mock Wazuh Alert` จำลอง SSH brute force บน Linux (`web-server-01`, `/var/log/auth.log`) แต่ proposal §3.1 จำกัด scope ไว้แค่ **Active Directory ผ่าน Windows Event Log (4625, 4740)** — ที่แปลกกว่านั้นคือ node `Normalize Alert` เขียน logic ไว้อ่าน `data.win.eventdata.*` (schema ของ Windows) อยู่แล้ว แปลว่า mock เดิมกับ normalize logic **ไม่ตรงกันเองตั้งแต่แรก** (mock ไม่เคยป้อนข้อมูลในฟิลด์ที่ normalize อ่านจริง)

**แก้ที่ไหน:** `n8n-workflow.json`
- `Mock Wazuh Alert` — เปลี่ยนเป็น Windows AD Event 4625+4740 เต็มรูปแบบ: agent `DC01`, target user `admin_somchai`, source IP `185.15.58.22`, `logonType: "3"`, `subStatus: "0xC000006A"` (ตรงกับ scenario ที่ร่างไว้ใน `study/02-windows-event-logs.md`)
- `Normalize Alert` — เพิ่ม derive ฟิลด์ใหม่ที่ต้องใช้ต่อ: `account_privilege` (lookup table ชั่วคราวแทนการถาม AD จริง), `distinct_accounts`, `attack_success` (default false), `cti_verdict` (default `"unknown"`)

**ตรวจสอบแล้ว:** จำลอง flow เต็มเส้นด้วย mock ใหม่ผ่าน API ตรง ได้ค่าตรงตามที่ออกแบบ

---

## 3. NCSC Categorisation + Escalation Matrix — จากไม่มีเลย เป็น endpoint จริง

**ปัญหา:** proposal วัตถุประสงค์ข้อ 1 ต้องการประเมินความรุนแรงตาม NCSC + สร้าง Escalation Matrix 3 ระดับ แต่โค้ดเดิมมีแค่ `severityMap()` แปลง Wazuh `rule.level` เป็น critical/high/medium/low ตรงๆ — ไม่ใช่กรอบ NCSC เลย และไม่มี escalation logic ใดๆ ทั้งสิ้น

**แก้ที่ไหน:** `Project/api.py` — endpoint ใหม่ `POST /assess/severity`
- Rubric ตายตัว (ไม่ใช่ LLM) แปลง 4 ตัวแปร (`account_privilege`, `attack_success`, `distinct_accounts`, `cti_verdict`) เป็น NCSC category C2–C6 พร้อมเหตุผล
- ตาราง Escalation แยกต่างหาก (`ESCALATION_TABLE`) map category → owner/tier/SLA
- `AssembleRequest`/`SavePlaybook` models เพิ่ม field รับผลนี้ไปแสดงใน markdown (section "NCSC Categorisation & Escalation Matrix" ในเอกสารที่ประกอบออกมา) และบันทึกลง `_STORE`

**ทำไมไม่ใช้ LLM ทั้งที่ ARCHITECTURE.md เขียนว่า "LLM node":** การตัดสิน category กระทบว่าใครถูกปลุกกลางดึกและ SLA เท่าไหร่ — เป็นจุดที่ผลกระทบของ hallucination สูงสุดในระบบ จึงเลือกโค้ดที่ unit test ได้แน่นอนแทน **นี่คือจุดที่เบี่ยงจากถ้อยคำใน ARCHITECTURE.md โดยตั้งใจ — ควรคุยกับทีม/อาจารย์ว่ายอมรับไหม**

**ข้อจำกัดที่ต้องรู้:** `cti_verdict` เป็น `"unknown"` เสมอตอนนี้เพราะ CTI enrichment (VirusTotal/AbuseIPDB) ยังไม่ implement — rubric ตีความ `"unknown"` แบบระมัดระวัง (เทียบเท่า suspicious ไม่ใช่ clean) กันประเมินต่ำเกินจริง

**ตรวจสอบแล้ว:** ทดสอบ 3 scenario ตรงเฉลย — Domain Admin+โจมตีสำเร็จ → C2, Domain Admin+ไม่สำเร็จ+CTI unknown → C3, Standard account+clean → C6

**เดินสาย n8n:** เพิ่ม node `Assess Severity` (HTTP Request → `POST /assess/severity`) คั่นระหว่าง `Normalize Alert` กับ `Get Sections` ผลลัพธ์ไหลผ่าน `Aggregate Sections` เข้า `Assemble Playbook` และ `Save Draft`

---

## 4. Knowledge Base: จาก 1 ส่วน เป็นครบ 3 ส่วนตามขอบเขต proposal §3.2

**ปัญหา:** KB มีแค่ `doc_type=playbook` (3 ไฟล์ที่ทีมเขียนเอง) — proposal ต้องการ 3 ส่วน: playbook ของทีม + เอกสารป้องกันรายเทคนิค + MITRE ATT&CK Mitigations ทางการผ่าน `mitreattack-python` และ `mitreattack-python` ไม่ได้อยู่ใน `requirements.txt` เลย

**แก้ที่ไหน:**
- `Project/01_ingest.py` — เพิ่ม field `doc_type` ในทุก chunk metadata (default `"playbook"` ถ้าไม่ระบุ), เปลี่ยน `glob` เป็น `rglob` ให้ดึงไฟล์ใน subfolder ได้
- `Project/api.py` — `/retrieve` เพิ่ม param `doc_types` (optional filter) และคืน `doc_type` ในแต่ละ chunk
- `Project/playbooks/defense/T1110_brute_force_defense.md` — ไฟล์ตัวอย่าง KB ส่วนที่ 2 (เอกสารป้องกันรายเทคนิค ไม่ผูก threat scenario)
- `Project/gen_mitre_kb.py` — สคริปต์ใหม่ ดึง MITRE Mitigations จริงผ่าน `mitreattack-python` (offline, อ่านจาก STIX data ที่ดาวน์โหลดมาเก็บใน `Project/mitre_data/` — ไม่ commit เข้า git เพราะไฟล์ ~50MB) → สร้างไฟล์ `doc_type=mitre` ใน `Project/playbooks/mitre/`
- `requirements.txt` — เพิ่ม `mitreattack-python`, เอา `pymisp` กับ `python-frontmatter` ออก (เช็คแล้วไม่เคยถูก import ที่ไหนเลยในโค้ด)

**รันจริงแล้ว ไม่ใช่แค่เขียนสคริปต์ทิ้งไว้:** ดาวน์โหลด `enterprise-attack.json` จริง รัน `gen_mitre_kb.py` ได้ไฟล์ mitigation จริง 7 ไฟล์ (T1110, T1110.001, T1110.003, T1078, T1003.001, T1550.002, T1021.001) ครอบคลุมทุก technique ที่ KB ปัจจุบันใช้

**หมายเหตุออกแบบ (สำคัญ):** MITRE Mitigations ไม่ได้ผูกกับ phase ใด phase หนึ่งโดยธรรมชาติ (ต่างจาก threat playbook) แต่ `/retrieve` กรอง phase แบบ exact match เสมอ จึง **จงใจ duplicate เนื้อหาเดิมลงทั้ง 3 phase** ในไฟล์ mitre แต่ละไฟล์ แลกกับพื้นที่เก็บที่มากขึ้น 3 เท่า — เป็นทางออกชั่วคราว ควรทบทวนตอนทำ retrieval tiering เต็มรูปแบบ

**ตรวจสอบแล้ว:** รัน `01_ingest.py` กับ KB เต็ม (playbook + defense + mitre) → 147 chunks จาก 11 ไฟล์ ครบ 3 phase, ทดสอบ `/retrieve` ทั้งแบบไม่กรอง (ได้ผสมทั้ง 3 doc_type) และกรอง `doc_types: ["mitre"]` (ได้เฉพาะ mitre) — ถูกต้องทั้งคู่

---

## ทดสอบ end-to-end ยังไงบ้าง

รันจำลอง flow เต็มเส้นตรงกับ API (ไม่ผ่าน n8n เพราะไม่มี Gemini key ในเครื่องที่แก้โค้ด):

```
mock alert (Windows AD) → normalize (derive account_privilege/cti_verdict/ฯลฯ)
  → POST /assess/severity → ได้ NCSC C3
  → GET /template/sections → ได้ 3 phase
  → POST /retrieve ทั้ง 3 phase → เจอ chunk ทุก phase
  → POST /playbooks/assemble → markdown มี Alert Context + NCSC/Escalation table + 3 phase section
  → POST /playbooks → บันทึกพร้อม ncsc_category/escalation_tier
  → GET /playbooks/lookup → คืนค่าที่บันทึกไว้ถูกต้อง
```

**ยังไม่ได้ทดสอบ:** รันผ่าน n8n instance จริงหรือเรียก Gemini API จริง — ต้อง Import workflow ใหม่แล้วกด Execute Workflow อีกรอบก่อนเชื่อว่า wiring ถูก 100%

---

## สิ่งที่ต้องคุยกับทีม/อาจารย์ก่อนไปต่อ

1. **NCSC/Escalation เป็น deterministic Python ไม่ใช่ LLM** ตามที่ ARCHITECTURE.md เขียนไว้ — ยอมรับการเบี่ยงนี้ไหม หรือแก้ ARCHITECTURE.md ให้ตรงกับของจริง
2. **MITRE mitigation chunk ที่ duplicate ลง 3 phase** — ทางออกชั่วคราว ควรทำ retrieval แบบ phase-agnostic จริงจังกว่านี้ไหม
3. **`cti_verdict` และ `account_privilege` ยังเป็นค่า placeholder** — ต้องต่อ CTI enrichment (VirusTotal/AbuseIPDB) และ AD group membership lookup จริงก่อนขึ้นระบบจริง

รายละเอียดเชิงลึกกว่านี้ (invariants, ของที่ยังเปราะ, ลำดับงานที่เหลือ) อยู่ใน `HANDOFF.md` §0–§7
